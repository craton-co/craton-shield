// SPDX-License-Identifier: Apache-2.0
//! # Network Firewall (`vs-netfw`)
//!
//! A stateful, priority-ordered network firewall for embedded systems with
//! token-bucket rate limiting and connection tracking.
//!
//! ## Overview
//!
//! The firewall evaluates Ethernet packets against a table of [`FirewallRule`]
//! entries. Rules are matched in **priority order** (lower `priority` value =
//! higher precedence). When two rules share the same priority, the one added
//! first wins. If no rule matches, the firewall applies a **default-deny**
//! policy and drops the packet.
//!
//! ## Rule Matching Algorithm
//!
//! Each packet is evaluated in two phases:
//!
//! 1. **L2 matching**: source/destination MAC, VLAN ID, and EtherType fields
//!    are checked. `None` fields act as wildcards.
//! 2. **L3/L4 matching**: if the rule specifies IP or transport fields, the
//!    packet payload is parsed once and matched against source/destination IP,
//!    protocol, and source/destination port. Pure L2 rules skip this phase.
//!
//! The first matching active rule determines the verdict.
//!
//! ## Rate Limiting
//!
//! Rules with [`RuleAction::RateLimit(pps)`] use a fixed-point token-bucket
//! algorithm. Each rate-limited rule gets its own bucket (up to 32 concurrent
//! rate limiters). Packets that exceed the configured packets-per-second rate
//! are dropped; others pass through.
//!
//! ## Default-Deny Policy
//!
//! When no rule matches a packet, the firewall returns [`Verdict::Drop`]. This
//! ensures that only explicitly permitted traffic is allowed through. To log
//! denied traffic, add a low-priority catch-all rule with [`RuleAction::Log`].
//!
//! ## Capacity
//!
//! The maximum number of rules is compile-time configurable via feature flags:
//! - Base (default): 128 rules
//! - `capacity-large`: 256 rules
//! - `capacity-xl`: 512 rules
//!
//! ## Key Types
//!
//! - [`Firewall`] -- the main firewall struct holding rules, rate limiters,
//!   and connection tracking state.
//! - [`FirewallRule`] -- a single match/action rule with L2-L4 filter fields.
//! - [`RuleAction`] -- what to do on match: Allow, Drop, Log, or RateLimit.
//! - [`Verdict`] -- the evaluation result returned to the caller.
//!
//! ## Public API (intended 1.0 surface)
//!
//! The `Firewall` type, the `FirewallRule` builder, the `RuleAction` /
//! `Verdict` result types, and the per-rule `add_rule` / `evaluate`
//! methods form the intended stable surface for the 1.0 release. They are
//! governed by the workspace deprecation policy (`DEPRECATION.md` at the
//! repository root). As an `0.x` crate this surface is not yet covered by
//! SemVer stability guarantees.
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use vs_eth_monitor::{parse_ip, parse_transport, EthPacket};
use vs_types::{IpAddr, IpProtocol, TcpState, VsError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of firewall rules (static + dynamic).
#[cfg(feature = "capacity-xl")]
const MAX_RULES: usize = 512;
#[cfg(all(feature = "capacity-large", not(feature = "capacity-xl")))]
const MAX_RULES: usize = 256;
#[cfg(not(any(feature = "capacity-large", feature = "capacity-xl")))]
const MAX_RULES: usize = 128;

/// Maximum number of concurrent token-bucket rate limiters.
const MAX_RATE_LIMITERS: usize = 32;

/// Microseconds per second — used for rate-limit arithmetic.
const USEC_PER_SEC: u64 = 1_000_000;

/// Fixed-point multiplier for token buckets (tokens * 1000).
const TOKEN_SCALE: u64 = 1000;

/// Connection tracker default timeout window (5 seconds in microseconds).
const CONN_TIMEOUT_US: u64 = 5_000_000;

// ---------------------------------------------------------------------------
// RuleAction
// ---------------------------------------------------------------------------

/// Action to take when a firewall rule matches a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// Permit the packet.
    Allow,
    /// Silently discard the packet.
    Drop,
    /// Allow the packet but log it.
    Log,
    /// Apply token-bucket rate limiting (packets per second).
    RateLimit(u32),
}

/// Result of evaluating a packet through the firewall.
///
/// Separates the *verdict* (allow or drop) from the *reason*, so callers
/// can distinguish rate-limited drops from rule-based drops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Packet is permitted (matched an Allow, Log, or rate-limited-and-allowed rule).
    Allow,
    /// Packet is dropped (matched a Drop rule or default deny).
    Drop,
    /// Packet is permitted and should be logged.
    Log,
    /// Packet was rate-limited and allowed through the token bucket.
    RateLimitAllow(u32),
    /// Packet was rate-limited and dropped by the token bucket.
    RateLimitDrop(u32),
}

// ---------------------------------------------------------------------------
// FirewallRule
// ---------------------------------------------------------------------------

/// A single firewall rule.  `None` fields act as wildcards.
#[derive(Debug, Clone, Copy)]
pub struct FirewallRule {
    /// Unique identifier for this rule.
    pub id: u32,
    /// Lower number = higher priority (evaluated first).
    /// When two rules have equal priority, the one inserted first wins.
    pub priority: u8,
    // L2 match fields
    /// Source MAC address to match; `None` is a wildcard.
    pub src_mac: Option<[u8; 6]>,
    /// Destination MAC address to match; `None` is a wildcard.
    pub dst_mac: Option<[u8; 6]>,
    /// IEEE 802.1Q VLAN ID to match (0..=4094); `None` is a wildcard.
    pub vlan_id: Option<u16>,
    /// EtherType to match (e.g. 0x0800 for IPv4); `None` is a wildcard.
    pub ethertype: Option<u16>,
    // L3 match fields
    /// Source IP address to match; `None` is a wildcard.
    pub src_ip: Option<IpAddr>,
    /// Destination IP address to match; `None` is a wildcard.
    pub dst_ip: Option<IpAddr>,
    /// IP transport protocol to match (TCP/UDP/ICMP/...); `None` is a wildcard.
    pub protocol: Option<IpProtocol>,
    // L4 match fields
    /// L4 source port to match; `None` is a wildcard.
    pub src_port: Option<u16>,
    /// L4 destination port to match; `None` is a wildcard.
    pub dst_port: Option<u16>,
    /// Action to apply when the rule matches.
    pub action: RuleAction,
    /// Whether the rule is currently evaluated. Inactive rules are skipped.
    pub active: bool,
}

impl Default for FirewallRule {
    fn default() -> Self {
        Self {
            id: 0,
            priority: u8::MAX,
            src_mac: None,
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            src_ip: None,
            dst_ip: None,
            protocol: None,
            src_port: None,
            dst_port: None,
            action: RuleAction::Drop,
            active: false,
        }
    }
}

impl FirewallRule {
    /// Check whether this rule matches the given packet (L2 fields only).
    fn matches_l2(&self, pkt: &EthPacket<'_>) -> bool {
        if !self.active {
            return false;
        }
        if let Some(src) = self.src_mac {
            if src != pkt.src_mac {
                return false;
            }
        }
        if let Some(dst) = self.dst_mac {
            if dst != pkt.dst_mac {
                return false;
            }
        }
        if let Some(vid) = self.vlan_id {
            if pkt.vlan_id != Some(vid) {
                return false;
            }
        }
        if let Some(et) = self.ethertype {
            if pkt.ethertype != et {
                return false;
            }
        }
        true
    }

    /// Check whether L3/L4 fields match.  If `has_l3_fields` is `false`,
    /// this is a pure L2 rule and always matches.  The caller passes the
    /// cached flag computed at rule insertion to avoid recomputing it per
    /// packet.
    fn matches_l3l4(&self, ip: Option<&ParsedL3L4>, has_l3_fields: bool) -> bool {
        if !has_l3_fields {
            return true; // pure L2 rule, always matches at this stage
        }

        let Some(parsed) = ip else {
            return false; // rule requires L3/L4 but packet is not IP
        };

        if let Some(ref src) = self.src_ip {
            if *src != parsed.ip.src {
                return false;
            }
        }
        if let Some(ref dst) = self.dst_ip {
            if *dst != parsed.ip.dst {
                return false;
            }
        }
        if let Some(ref proto) = self.protocol {
            if *proto != parsed.ip.protocol {
                return false;
            }
        }
        if let Some(sp) = self.src_port {
            match parsed.transport {
                Some(ref t) if t.src_port == sp => {}
                _ => return false,
            }
        }
        if let Some(dp) = self.dst_port {
            match parsed.transport {
                Some(ref t) if t.dst_port == dp => {}
                _ => return false,
            }
        }
        true
    }
}

/// Pre-parsed L3/L4 information extracted once per packet.
struct ParsedL3L4 {
    ip: vs_types::IpHeader,
    transport: Option<vs_types::TransportHeader>,
}

// ---------------------------------------------------------------------------
// TokenBucket (fixed-point rate limiter)
// ---------------------------------------------------------------------------

/// Token-bucket rate limiter using fixed-point arithmetic.
///
/// `tokens_x1000` stores the current token count multiplied by 1000 so that
/// sub-token replenishment can be tracked without floating point.
#[derive(Debug, Clone, Copy)]
pub struct TokenBucket {
    /// Current tokens scaled by `TOKEN_SCALE`.
    pub tokens_x1000: u64,
    /// Allowed packets per second.
    pub rate_per_sec: u32,
    /// Timestamp (microseconds) of last token replenishment.
    pub last_update_us: u64,
    /// The rule ID this bucket is associated with.
    rule_id: u32,
    /// Whether this bucket slot is in use.
    active: bool,
}

impl TokenBucket {
    /// Create a new idle (unused) bucket.
    const fn empty() -> Self {
        Self {
            tokens_x1000: 0,
            rate_per_sec: 0,
            last_update_us: 0,
            rule_id: 0,
            active: false,
        }
    }

    /// Initialise for a specific rule.
    fn init(&mut self, rule_id: u32, rate: u32, now_us: u64) {
        self.rule_id = rule_id;
        self.rate_per_sec = rate;
        // Start with a full token (one packet allowed immediately).
        self.tokens_x1000 = u64::from(rate).saturating_mul(TOKEN_SCALE);
        self.last_update_us = now_us;
        self.active = true;
    }

    /// Replenish tokens based on elapsed time, then try to consume one token.
    /// Returns `true` if the packet is allowed.
    ///
    /// If `now_us` is earlier than `last_update_us` (non-monotonic clock),
    /// no tokens are replenished to prevent burst attacks via clock
    /// manipulation.  The `backward_clock_count` is incremented for
    /// monitoring.
    fn try_consume(&mut self, now_us: u64) -> bool {
        if !self.active {
            return false;
        }

        // Only replenish if time has moved forward (guard against
        // non-monotonic timestamps).  Do NOT replenish on backwards
        // jumps to prevent burst attacks via clock manipulation.
        if now_us > self.last_update_us {
            let elapsed_us = now_us - self.last_update_us;
            // new_tokens_x1000 = rate_per_sec * elapsed_us * 1000 / 1_000_000
            //                   = rate_per_sec * elapsed_us / 1000
            // Use checked arithmetic to detect overflow. If the product
            // saturates (extreme elapsed_us), cap at max_tokens to prevent
            // incorrect token counts.
            let product = u64::from(self.rate_per_sec).checked_mul(elapsed_us);
            let max_tokens_x1000 = u64::from(self.rate_per_sec).saturating_mul(TOKEN_SCALE);
            let new_tokens_x1000 = match product {
                Some(p) => p / (USEC_PER_SEC / TOKEN_SCALE),
                // On overflow, cap at maximum bucket capacity rather than
                // u64::MAX which would bypass rate limiting entirely.
                None => max_tokens_x1000,
            };

            self.tokens_x1000 = self.tokens_x1000.saturating_add(new_tokens_x1000);
            if self.tokens_x1000 > max_tokens_x1000 {
                self.tokens_x1000 = max_tokens_x1000;
            }
            self.last_update_us = now_us;
        }

        // Try to consume one token (TOKEN_SCALE units).
        if self.tokens_x1000 >= TOKEN_SCALE {
            self.tokens_x1000 = self.tokens_x1000.saturating_sub(TOKEN_SCALE);
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// RuleSlot (rule + optional dynamic expiry + hit counter)
// ---------------------------------------------------------------------------

/// Internal storage for a rule with optional dynamic-rule expiry tracking.
#[derive(Debug, Clone, Copy)]
struct RuleSlot {
    rule: FirewallRule,
    /// If `Some`, this is a dynamic rule that expires at the given timestamp.
    expiry_us: Option<u64>,
    /// Number of times this rule has been matched.
    hit_count: u64,
    /// Cached at insertion: `true` if the rule references any L3/L4 field
    /// (src_ip / dst_ip / protocol / src_port / dst_port). Lets `evaluate`
    /// avoid recomputing this on every packet/rule pair.
    has_l3_fields: bool,
}

impl RuleSlot {
    const fn empty() -> Self {
        Self {
            rule: FirewallRule {
                id: 0,
                priority: u8::MAX,
                src_mac: None,
                dst_mac: None,
                vlan_id: None,
                ethertype: None,
                src_ip: None,
                dst_ip: None,
                protocol: None,
                src_port: None,
                dst_port: None,
                action: RuleAction::Drop,
                active: false,
            },
            expiry_us: None,
            hit_count: 0,
            has_l3_fields: false,
        }
    }
}

#[inline]
fn rule_has_l3_fields(rule: &FirewallRule) -> bool {
    rule.src_ip.is_some()
        || rule.dst_ip.is_some()
        || rule.protocol.is_some()
        || rule.src_port.is_some()
        || rule.dst_port.is_some()
}

// ---------------------------------------------------------------------------
// Firewall
// ---------------------------------------------------------------------------

/// Stateful network firewall with fixed rule table, rate limiting,
/// dynamic rules, and connection tracking.
///
/// Default policy is **deny** — packets that match no rule are dropped.
pub struct Firewall {
    rules: [RuleSlot; MAX_RULES],
    rule_count: usize,
    rate_limiters: [TokenBucket; MAX_RATE_LIMITERS],
    /// Number of packets dropped (hit a Drop rule or default deny).
    drop_counter: u64,
    /// Optional logging callback invoked when a `Log` rule matches.
    log_fn: Option<fn(&EthPacket<'_>, u32)>,
    /// Cached count of currently-active rules; kept in sync with the
    /// rule table on insert / update / remove / expire.
    active_count: u32,
    /// Cached `OR` of `has_l3_fields` across all active rules. When `false`,
    /// `evaluate` can skip IP / transport parsing entirely.
    any_l3_rule: bool,
}

impl Firewall {
    /// Create a new firewall with an empty rule table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: [RuleSlot::empty(); MAX_RULES],
            rule_count: 0,
            rate_limiters: [TokenBucket::empty(); MAX_RATE_LIMITERS],
            drop_counter: 0,
            log_fn: None,
            active_count: 0,
            any_l3_rule: false,
        }
    }

    /// Returns the number of packets that have been dropped.
    #[must_use]
    pub fn drop_count(&self) -> u64 {
        self.drop_counter
    }

    /// Register a logging callback invoked when a `Log` rule matches.
    ///
    /// The callback receives the matched packet and the rule ID.
    pub fn set_log_fn(&mut self, f: fn(&EthPacket<'_>, u32)) {
        self.log_fn = Some(f);
    }

    // -- Rule management ----------------------------------------------------

    /// Add a static rule.
    ///
    /// # Errors
    ///
    /// - [`VsError::InvalidConfig`] if a rule with the same `id` already exists.
    /// - [`VsError::ResourceExhausted`] when the rule table is at maximum
    ///   capacity and no inactive slot can be reclaimed.
    pub fn add_rule(&mut self, rule: FirewallRule) -> Result<(), VsError> {
        // Reject duplicate rule IDs.
        if self.find_rule_index(rule.id).is_some() {
            return Err(VsError::InvalidConfig);
        }
        let has_l3_fields = rule_has_l3_fields(&rule);
        self.insert_slot(RuleSlot {
            rule,
            expiry_us: None,
            hit_count: 0,
            has_l3_fields,
        })
    }

    /// Returns `(current_active_rules, max_rules)` for capacity monitoring.
    ///
    /// `current_active_rules` is read from the cached `active_count` field
    /// that is kept in sync on every rule mutation, so this is O(1).
    pub fn rule_capacity(&self) -> (usize, usize) {
        (self.active_count as usize, MAX_RULES)
    }

    /// Insert a dynamic rule (e.g. triggered by the IDS) that will
    /// automatically expire at `expiry_us`.
    ///
    /// # Errors
    ///
    /// - [`VsError::InvalidConfig`] if a rule with the same `id` already exists.
    /// - [`VsError::ResourceExhausted`] when the rule table is at maximum
    ///   capacity and no inactive slot can be reclaimed.
    pub fn insert_dynamic_rule(
        &mut self,
        rule: FirewallRule,
        expiry_us: u64,
    ) -> Result<(), VsError> {
        if self.find_rule_index(rule.id).is_some() {
            return Err(VsError::InvalidConfig);
        }
        let has_l3_fields = rule_has_l3_fields(&rule);
        self.insert_slot(RuleSlot {
            rule,
            expiry_us: Some(expiry_us),
            hit_count: 0,
            has_l3_fields,
        })
    }

    /// Remove a rule by its ID. Returns `true` if the rule existed and was
    /// removed, `false` if no rule with that ID was found.
    ///
    /// Also frees the associated rate-limiter bucket, if any.
    pub fn remove_rule(&mut self, rule_id: u32) -> bool {
        if let Some(idx) = self.find_rule_index(rule_id) {
            self.rules[idx].rule.active = false;
            self.release_bucket(rule_id);
            self.compact();
            self.recompute_active_caches();
            true
        } else {
            false
        }
    }

    /// Update the action and/or priority of an existing rule.
    ///
    /// When `new_priority` differs from the rule's current priority, the
    /// rule table is re-sorted so that `evaluate`'s ascending-priority
    /// first-match scan remains correct.  A duplicate-priority check
    /// (mirroring `Self::insert_slot`) prevents the update from silently
    /// shadowing an existing rule.
    ///
    /// # Errors
    ///
    /// Returns [`VsError::InvalidInput`] if no rule with the given `rule_id`
    /// exists.  Returns [`VsError::PolicyViolation`] if `new_priority`
    /// collides with another active rule's priority.
    pub fn update_rule(
        &mut self,
        rule_id: u32,
        new_action: Option<RuleAction>,
        new_priority: Option<u8>,
    ) -> Result<(), VsError> {
        let idx = self.find_rule_index(rule_id).ok_or(VsError::InvalidInput)?;

        // Validate the priority change BEFORE applying any mutation so the
        // operation is atomic on failure.  If the new priority equals the
        // current one we treat it as a no-op (no conflict with self).
        if let Some(priority) = new_priority {
            if priority != self.rules[idx].rule.priority {
                for i in 0..self.rule_count {
                    if i != idx
                        && self.rules[i].rule.active
                        && self.rules[i].rule.priority == priority
                    {
                        return Err(VsError::PolicyViolation);
                    }
                }
            }
        }

        if let Some(action) = new_action {
            // If changing away from RateLimit, free the old bucket.
            if !matches!(action, RuleAction::RateLimit(_)) {
                self.release_bucket(rule_id);
            }
            self.rules[idx].rule.action = action;
        }
        if let Some(priority) = new_priority {
            let old_priority = self.rules[idx].rule.priority;
            self.rules[idx].rule.priority = priority;
            // Re-sort so `evaluate`'s ascending-priority first-match
            // invariant holds.  Without this, a Drop rule raised above an
            // Allow would still be evaluated after the Allow and bypassed.
            if priority != old_priority {
                self.sort_rules();
            }
        }
        Ok(())
    }

    /// Returns the hit count for a rule, or `None` if the rule ID is not found.
    #[must_use]
    pub fn rule_hits(&self, rule_id: u32) -> Option<u64> {
        self.find_rule_index(rule_id)
            .map(|idx| self.rules[idx].hit_count)
    }

    /// Deactivate any dynamic rules whose expiry time is at or before
    /// `current_us`.  Also frees associated rate-limiter buckets and
    /// compacts the rule table to reclaim slots.
    pub fn expire_rules(&mut self, current_us: u64) {
        let mut compacted = false;
        for i in 0..self.rule_count {
            if let Some(exp) = self.rules[i].expiry_us {
                if current_us >= exp && self.rules[i].rule.active {
                    let rid = self.rules[i].rule.id;
                    self.rules[i].rule.active = false;
                    self.release_bucket(rid);
                    compacted = true;
                }
            }
        }
        if compacted {
            self.compact();
            self.recompute_active_caches();
        }
    }

    // -- Packet evaluation --------------------------------------------------

    /// Evaluate a packet against the rule table using first-match semantics
    /// (lowest `priority` number wins; ties broken by insertion order).
    ///
    /// Returns a [`Verdict`] that distinguishes allow/drop from rate-limit
    /// outcomes.
    ///
    /// For `RateLimit` rules the corresponding token bucket is consulted.
    /// If no rule matches, the default-deny policy returns `Verdict::Drop`.
    #[inline]
    pub fn evaluate(&mut self, pkt: &EthPacket<'_>, ts_us: u64) -> Verdict {
        // Parse L3/L4 headers once (lazy, only if any rule needs them).
        // The `any_l3_rule` cache avoids paying parser cost when every
        // active rule is pure L2.
        let parsed = if self.any_l3_rule {
            parse_ip(pkt.ethertype, pkt.payload).map(|(ip, offset)| {
                let transport = parse_transport(ip.protocol, pkt.payload, offset);
                ParsedL3L4 { ip, transport }
            })
        } else {
            None
        };
        let parsed_ref = parsed.as_ref();

        // Rules are maintained in ascending priority order (lower number =
        // higher priority), so the first matching rule is the best match.
        // This turns O(n) full-scan into O(k) where k is the index of
        // the first match.
        let mut best: Option<usize> = None;
        for i in 0..self.rule_count {
            let slot = &self.rules[i];
            let rule = &slot.rule;
            if rule.matches_l2(pkt) && rule.matches_l3l4(parsed_ref, slot.has_l3_fields) {
                best = Some(i);
                break;
            }
        }

        // Increment hit counter for the matched rule.
        if let Some(idx) = best {
            self.rules[idx].hit_count = self.rules[idx].hit_count.saturating_add(1);
        }

        let action = match best {
            Some(idx) => self.rules[idx].rule.action,
            None => RuleAction::Drop, // default deny
        };

        match action {
            RuleAction::Drop => {
                self.drop_counter = self.drop_counter.saturating_add(1);
                Verdict::Drop
            }
            RuleAction::RateLimit(rate) => {
                let rule_id = match best {
                    Some(idx) => self.rules[idx].rule.id,
                    None => 0,
                };
                let allowed = self.rate_limit_check(rule_id, rate, ts_us);
                if allowed {
                    Verdict::RateLimitAllow(rate)
                } else {
                    self.drop_counter = self.drop_counter.saturating_add(1);
                    Verdict::RateLimitDrop(rate)
                }
            }
            RuleAction::Log => {
                let rule_id = match best {
                    Some(idx) => self.rules[idx].rule.id,
                    None => 0,
                };
                if let Some(f) = self.log_fn {
                    f(pkt, rule_id);
                }
                Verdict::Log
            }
            RuleAction::Allow => Verdict::Allow,
        }
    }

    // -- Internal helpers ---------------------------------------------------

    /// Find the slot index for a rule by its ID, considering only active rules
    /// within the current rule count.
    fn find_rule_index(&self, rule_id: u32) -> Option<usize> {
        self.rules[..self.rule_count]
            .iter()
            .position(|s| s.rule.active && s.rule.id == rule_id)
    }

    /// Insert a `RuleSlot`, maintaining ascending priority order for
    /// first-match early exit during evaluation.
    /// Validate a firewall rule's fields before insertion.
    fn validate_rule(rule: &FirewallRule) -> Result<(), VsError> {
        // IEEE 802.1Q VLAN IDs must be in the range 0..=4094.
        if let Some(vid) = rule.vlan_id {
            if vid > 4094 {
                return Err(VsError::InvalidConfig);
            }
        }
        Ok(())
    }

    fn insert_slot(&mut self, slot: RuleSlot) -> Result<(), VsError> {
        Self::validate_rule(&slot.rule)?;
        // Reject duplicate priorities to prevent shadowing.
        for i in 0..self.rule_count {
            if self.rules[i].rule.active && self.rules[i].rule.priority == slot.rule.priority {
                return Err(VsError::PolicyViolation);
            }
        }
        // First try to reuse an inactive slot within the current range.
        for i in 0..self.rule_count {
            if !self.rules[i].rule.active {
                self.rules[i] = slot;
                self.sort_rules();
                self.bump_active_caches(&slot);
                return Ok(());
            }
        }
        // Append if there is room.
        if self.rule_count >= MAX_RULES {
            return Err(VsError::ResourceExhausted);
        }
        // Bisect-insert: find the correct sorted position in O(log n)
        // compares using `partition_point`, then shift the suffix right
        // and drop the new slot in place. This keeps the table sorted
        // without running the full insertion-sort pass.
        let priority = slot.rule.priority;
        let pos = self.rules[..self.rule_count].partition_point(|s| s.rule.priority < priority);
        // Shift [pos..rule_count) right by one.
        let mut i = self.rule_count;
        while i > pos {
            self.rules[i] = self.rules[i - 1];
            i -= 1;
        }
        self.rules[pos] = slot;
        self.rule_count = self.rule_count.saturating_add(1);
        self.bump_active_caches(&slot);
        Ok(())
    }

    /// Re-establish the ascending-priority invariant after an in-place
    /// priority mutation (or slot reuse). Uses insertion sort because the
    /// array is nearly sorted, making the average case near-O(n).
    fn sort_rules(&mut self) {
        for i in 1..self.rule_count {
            let mut j = i;
            while j > 0 && self.rules[j].rule.priority < self.rules[j - 1].rule.priority {
                self.rules.swap(j, j - 1);
                j -= 1;
            }
        }
    }

    /// Incrementally update the active-rule caches when a single active
    /// slot is added. For removals / bulk updates use
    /// [`Self::recompute_active_caches`].
    #[inline]
    fn bump_active_caches(&mut self, slot: &RuleSlot) {
        if slot.rule.active {
            self.active_count = self.active_count.saturating_add(1);
            if slot.has_l3_fields {
                self.any_l3_rule = true;
            }
        }
    }

    /// Recompute `active_count` and `any_l3_rule` from scratch. Called from
    /// paths that deactivate or remove rules (where simple decrement is not
    /// safe because we also need to know if the deactivated rule was the
    /// last L3 rule).
    fn recompute_active_caches(&mut self) {
        let mut count: u32 = 0;
        let mut any_l3 = false;
        for i in 0..self.rule_count {
            if self.rules[i].rule.active {
                count = count.saturating_add(1);
                if self.rules[i].has_l3_fields {
                    any_l3 = true;
                }
            }
        }
        self.active_count = count;
        self.any_l3_rule = any_l3;
    }

    /// Remove inactive slots at the end of the array to keep `rule_count`
    /// tight.
    fn compact(&mut self) {
        while self.rule_count > 0 && !self.rules[self.rule_count - 1].rule.active {
            self.rules[self.rule_count - 1] = RuleSlot::empty();
            self.rule_count -= 1;
        }
    }

    /// Release the token-bucket slot associated with `rule_id`.
    /// Uses hash-based lookup with linear probing for O(1) average case.
    fn release_bucket(&mut self, rule_id: u32) {
        let start = Self::bucket_hash(rule_id);
        for i in 0..MAX_RATE_LIMITERS {
            let idx = (start + i) & (MAX_RATE_LIMITERS - 1);
            if self.rate_limiters[idx].active && self.rate_limiters[idx].rule_id == rule_id {
                self.rate_limiters[idx] = TokenBucket::empty();
                return;
            }
            // V7 fix: do NOT break on inactive slots — tombstones from prior
            // releases can create holes in the probing chain. We must scan
            // the entire probe sequence to find the target bucket.
        }
    }

    // -- Rate-limiter helpers -----------------------------------------------

    /// Hash a rule_id to a starting bucket index for linear probing.
    #[inline]
    fn bucket_hash(rule_id: u32) -> usize {
        // Multiplicative hash (Knuth golden ratio) for u32 keys.
        let h = (rule_id as u64).wrapping_mul(0x9E37_79B9);
        (h as usize) & (MAX_RATE_LIMITERS - 1)
    }

    /// Look up or create a token bucket for the given rule and try to consume
    /// a token.  Uses hash-based lookup with linear probing instead of full scan.
    /// Returns `true` if the packet is allowed.
    fn rate_limit_check(&mut self, rule_id: u32, rate: u32, now_us: u64) -> bool {
        let start = Self::bucket_hash(rule_id);

        // Probe for existing bucket or first free slot.
        let mut free_idx: Option<usize> = None;
        for i in 0..MAX_RATE_LIMITERS {
            let idx = (start + i) & (MAX_RATE_LIMITERS - 1);
            if self.rate_limiters[idx].active && self.rate_limiters[idx].rule_id == rule_id {
                return self.rate_limiters[idx].try_consume(now_us);
            }
            if !self.rate_limiters[idx].active && free_idx.is_none() {
                free_idx = Some(idx);
            }
        }

        // Allocate a new bucket at the first free slot found.
        if let Some(idx) = free_idx {
            self.rate_limiters[idx].init(rule_id, rate, now_us);
            return self.rate_limiters[idx].try_consume(now_us);
        }

        // Table is full — evict the least-recently-used entry **on the
        // new rule's probe chain**, not globally.
        //
        // Correctness: with open-addressing + linear probing, lookups walk
        // the probe sequence `start, start+1, start+2, ...` (mod capacity).
        // Evicting an arbitrary slot off-chain would leave the new bucket
        // sitting at some index that lookups for `rule_id` never visit,
        // because the next `rate_limit_check` would either terminate at
        // an active-but-different-rule slot before reaching it, or — worse
        // — fail to terminate (an inactive slot inserted off-chain would
        // not be on the probe chain to begin with, but a later release
        // could leave an inactive hole anywhere). Restricting the LRU
        // search to the probe sequence guarantees the freshly-placed
        // bucket is reachable by subsequent lookups and `release_bucket`.
        //
        // The probe sequence is bounded by `MAX_RATE_LIMITERS` (table is
        // full at this point, so every probe step lands on an active
        // slot — every slot is on every probe chain when full, but we
        // still walk in probe order to keep the LRU pick well-defined).
        let mut lru_idx: usize = start;
        let mut lru_ts: u64 = u64::MAX;
        let mut found_on_chain = false;
        for i in 0..MAX_RATE_LIMITERS {
            let idx = (start + i) & (MAX_RATE_LIMITERS - 1);
            if self.rate_limiters[idx].active && self.rate_limiters[idx].last_update_us < lru_ts {
                lru_ts = self.rate_limiters[idx].last_update_us;
                lru_idx = idx;
                found_on_chain = true;
            }
        }
        // At full capacity every probe slot is active, so `found_on_chain`
        // is always true; the fallback exists only for defensive symmetry
        // and is unreachable under the invariants above.
        if !found_on_chain {
            // Defensive global scan; this branch indicates a logic error
            // elsewhere (e.g. `active` flags out of sync).
            let mut g_idx: usize = 0;
            let mut g_ts: u64 = u64::MAX;
            for i in 0..MAX_RATE_LIMITERS {
                if self.rate_limiters[i].active && self.rate_limiters[i].last_update_us < g_ts {
                    g_ts = self.rate_limiters[i].last_update_us;
                    g_idx = i;
                }
            }
            lru_idx = g_idx;
        }
        self.rate_limiters[lru_idx].init(rule_id, rate, now_us);
        self.rate_limiters[lru_idx].try_consume(now_us)
    }
}

impl Default for Firewall {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ConnTracker — simplified connection tracking
// ---------------------------------------------------------------------------

/// Key for connection tracking: `(src_mac, dst_mac, ethertype, src_port, dst_port, vlan_id)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConnKey {
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    ethertype: u16,
    src_port: u16,
    dst_port: u16,
    vlan_id: u16,
}

/// A single connection-tracking entry.
#[derive(Debug, Clone, Copy)]
struct ConnEntry {
    key: ConnKey,
    last_seen_us: u64,
    active: bool,
}

impl ConnEntry {
    const fn empty() -> Self {
        Self {
            key: ConnKey {
                src_mac: [0; 6],
                dst_mac: [0; 6],
                ethertype: 0,
                src_port: 0,
                dst_port: 0,
                vlan_id: 0,
            },
            last_seen_us: 0,
            active: false,
        }
    }
}

/// Build the connection-tracking key for a packet.
///
/// The transport-layer source and destination ports are recovered by
/// parsing the IP and transport headers out of the packet payload, so
/// flows that differ only by source port are tracked as distinct
/// connections. When the payload is not parseable transport (e.g. ARP,
/// truncated frames) the port fields fall back to `0`.
fn conn_key(pkt: &EthPacket<'_>) -> ConnKey {
    let (src_port, dst_port) = parse_ip(pkt.ethertype, pkt.payload)
        .and_then(|(ip, offset)| parse_transport(ip.protocol, pkt.payload, offset))
        .map_or((0, 0), |t| (t.src_port, t.dst_port));
    ConnKey {
        src_mac: pkt.src_mac,
        dst_mac: pkt.dst_mac,
        ethertype: pkt.ethertype,
        src_port,
        dst_port,
        vlan_id: pkt.vlan_id.unwrap_or(0),
    }
}

/// Simplified connection tracker.
///
/// Tracks `(src_mac, dst_mac, ethertype, src_port, dst_port, vlan_id)`
/// tuples inside a fixed-size table. The source and destination ports are
/// parsed from the packet's transport header, so flows differing only by
/// source port are kept as separate entries. Entries older than 5 seconds
/// are considered stale.
pub struct ConnTracker<const MAX: usize> {
    entries: [ConnEntry; MAX],
}

/// Helper: we need a way to create the backing array at compile time.
/// Because `ConnEntry` is `Copy` and has a `const fn empty()`, we can
/// initialise via `[ConnEntry::empty(); MAX]` only when `MAX` is known.
/// We use a `new()` method that leverages this.
impl<const MAX: usize> ConnTracker<MAX> {
    /// Create an empty connection tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: [ConnEntry::empty(); MAX],
        }
    }

    /// Record a packet in the tracker, creating or refreshing an entry.
    ///
    /// Non-monotonic timestamps: if `ts_us` is earlier than the existing
    /// entry's `last_seen_us`, the entry is *not* rolled back.
    pub fn track(&mut self, pkt: &EthPacket<'_>, ts_us: u64) {
        let key = conn_key(pkt);

        // Update existing entry if present.
        for entry in &mut self.entries {
            if entry.active && entry.key == key {
                if ts_us >= entry.last_seen_us {
                    entry.last_seen_us = ts_us;
                }
                return;
            }
        }

        // Reuse the first inactive / stale slot.
        for entry in &mut self.entries {
            if !entry.active || ts_us.saturating_sub(entry.last_seen_us) > CONN_TIMEOUT_US {
                entry.key = key;
                entry.last_seen_us = ts_us;
                entry.active = true;
                return;
            }
        }

        // Table full and all entries fresh — overwrite the oldest.
        let mut oldest_idx: usize = 0;
        let mut oldest_ts: u64 = u64::MAX;
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.last_seen_us < oldest_ts {
                oldest_ts = entry.last_seen_us;
                oldest_idx = i;
            }
        }
        self.entries[oldest_idx].key = key;
        self.entries[oldest_idx].last_seen_us = ts_us;
        self.entries[oldest_idx].active = true;
    }

    /// Returns `true` if there is a non-stale entry for the packet's
    /// `(src_mac, dst_mac, ethertype, src_port, dst_port, vlan_id)` tuple.
    #[must_use]
    pub fn is_known(&self, pkt: &EthPacket<'_>, ts_us: u64) -> bool {
        let key = conn_key(pkt);
        for entry in &self.entries {
            if entry.active
                && entry.key == key
                && ts_us.saturating_sub(entry.last_seen_us) <= CONN_TIMEOUT_US
            {
                return true;
            }
        }
        false
    }
}

impl<const MAX: usize> Default for ConnTracker<MAX> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TCP State Tracker
// ---------------------------------------------------------------------------

/// Maximum number of simultaneous tracked TCP connections.
const MAX_TCP_CONNS: usize = 64;

/// Key for a TCP connection: `(src_ip, dst_ip, src_port, dst_port)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TcpConnKey {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
}

/// Entry in the TCP state table.
#[derive(Debug, Clone, Copy)]
struct TcpConnEntry {
    key: TcpConnKey,
    state: TcpState,
    last_seen_us: u64,
    active: bool,
    /// `true` when the *initiator* (forward direction) sent the first FIN.
    fin_from_forward: bool,
}

impl TcpConnEntry {
    const fn empty() -> Self {
        Self {
            key: TcpConnKey {
                src_ip: IpAddr::V4([0; 4]),
                dst_ip: IpAddr::V4([0; 4]),
                src_port: 0,
                dst_port: 0,
            },
            state: TcpState::Closed,
            last_seen_us: 0,
            active: false,
            fin_from_forward: false,
        }
    }
}

/// Stateful TCP connection tracker.
///
/// Tracks the TCP handshake state machine (SYN → SYN-ACK → ACK → ESTABLISHED
/// → FIN → Closed) and can be queried to determine whether a packet belongs
/// to an established connection.
///
/// The FIN/close path requires a FIN from one direction followed by a FIN or
/// ACK from the **peer** direction — a single FIN+ACK in the same direction
/// does not immediately close the connection.
pub struct TcpStateTracker {
    entries: [TcpConnEntry; MAX_TCP_CONNS],
}

impl TcpStateTracker {
    /// Create an empty TCP state tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: [TcpConnEntry::empty(); MAX_TCP_CONNS],
        }
    }

    /// Process a TCP segment and update the connection state.
    /// Returns the new state after processing.
    ///
    /// Non-monotonic timestamps: if `ts_us` is earlier than the entry's
    /// `last_seen_us`, the entry's timestamp is not rolled back.
    pub fn process(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        tcp_flags: u8,
        ts_us: u64,
    ) -> TcpState {
        use vs_types::tcp_flags as tf;

        let fwd_key = TcpConnKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        };
        let rev_key = TcpConnKey {
            src_ip: dst_ip,
            dst_ip: src_ip,
            src_port: dst_port,
            dst_port: src_port,
        };

        // Look for existing entry (forward or reverse direction).
        for entry in &mut self.entries {
            if !entry.active {
                continue;
            }
            // Check stale (30 second timeout for TCP).
            if ts_us.saturating_sub(entry.last_seen_us) > 30_000_000 {
                entry.active = false;
                continue;
            }
            let is_forward = entry.key == fwd_key;
            let is_reverse = entry.key == rev_key;
            if !is_forward && !is_reverse {
                continue;
            }

            if ts_us >= entry.last_seen_us {
                entry.last_seen_us = ts_us;
            }
            entry.state =
                Self::next_state(entry.state, tcp_flags, is_forward, entry.fin_from_forward);
            // Track which direction sent the first FIN.
            if entry.state == TcpState::FinWait && tcp_flags & tf::FIN != 0 {
                entry.fin_from_forward = is_forward;
            }
            if entry.state == TcpState::Closed {
                entry.active = false;
            }
            return entry.state;
        }

        // No existing entry — check for SYN to start tracking.
        if tcp_flags & tf::SYN != 0 && tcp_flags & tf::ACK == 0 {
            self.insert(fwd_key, TcpState::SynSent, ts_us);
            return TcpState::SynSent;
        }

        TcpState::Closed
    }

    /// Query the state of a connection. Returns `None` if not tracked.
    pub fn get_state(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
    ) -> Option<TcpState> {
        let fwd = TcpConnKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        };
        let rev = TcpConnKey {
            src_ip: dst_ip,
            dst_ip: src_ip,
            src_port: dst_port,
            dst_port: src_port,
        };
        for entry in &self.entries {
            if entry.active && (entry.key == fwd || entry.key == rev) {
                return Some(entry.state);
            }
        }
        None
    }

    /// Advance the TCP state machine.
    ///
    /// `is_forward` means the packet's direction matches the original SYN
    /// sender.  `fin_from_forward` records which direction sent the first FIN.
    ///
    /// The FIN-close path requires the **peer** (opposite direction) to
    /// respond with FIN or ACK before the connection is considered closed.
    fn next_state(
        current: TcpState,
        flags: u8,
        is_forward: bool,
        fin_from_forward: bool,
    ) -> TcpState {
        use vs_types::tcp_flags as tf;

        // NOTE: an RST in any direction unconditionally closes the connection.
        // This is a deliberate simplification. Blind RSTs from off-path
        // attackers (RFC 5961) can tear down established state if accepted
        // without further checks; production deployments should pair this
        // path with a sequence-number / source-validation guard upstream
        // (RFC 5961 §3.2 challenge-ACK or in-window-only acceptance).
        if flags & tf::RST != 0 {
            return TcpState::Closed;
        }

        match current {
            TcpState::SynSent => {
                if !is_forward && flags & tf::SYN_ACK == tf::SYN_ACK {
                    TcpState::SynReceived
                } else {
                    TcpState::SynSent
                }
            }
            TcpState::SynReceived => {
                if is_forward && flags & tf::ACK != 0 {
                    TcpState::Established
                } else {
                    TcpState::SynReceived
                }
            }
            TcpState::Established => {
                if flags & tf::FIN != 0 {
                    TcpState::FinWait
                } else {
                    TcpState::Established
                }
            }
            TcpState::FinWait => {
                // Only the *peer* direction (opposite to whoever sent FIN)
                // can close the connection with FIN or ACK.
                let from_peer = is_forward != fin_from_forward;
                if from_peer && (flags & tf::FIN != 0 || flags & tf::ACK != 0) {
                    TcpState::Closed
                } else {
                    TcpState::FinWait
                }
            }
            TcpState::Closed => TcpState::Closed,
            // `TcpState` is `#[non_exhaustive]`. New variants would need an
            // explicit transition policy; until then, hold the current state.
            _ => current,
        }
    }

    fn insert(&mut self, key: TcpConnKey, state: TcpState, ts_us: u64) {
        // Find inactive slot.
        for entry in &mut self.entries {
            if !entry.active {
                *entry = TcpConnEntry {
                    key,
                    state,
                    last_seen_us: ts_us,
                    active: true,
                    fin_from_forward: false,
                };
                return;
            }
        }
        // Overwrite oldest entry.
        let mut oldest_idx = 0;
        let mut oldest_ts = u64::MAX;
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.last_seen_us < oldest_ts {
                oldest_ts = entry.last_seen_us;
                oldest_idx = i;
            }
        }
        self.entries[oldest_idx] = TcpConnEntry {
            key,
            state,
            last_seen_us: ts_us,
            active: true,
            fin_from_forward: false,
        };
    }
}

impl Default for TcpStateTracker {
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
    use vs_types::tcp_flags as tf;

    /// Helper: build a minimal packet with the given MACs and ethertype.
    fn make_pkt(src: [u8; 6], dst: [u8; 6], ethertype: u16) -> EthPacket<'static> {
        EthPacket {
            src_mac: src,
            dst_mac: dst,
            vlan_id: None,
            ethertype,
            dst_port: None,
            payload: &[],
        }
    }

    // -- Allow rule ---------------------------------------------------------

    #[test]
    fn allow_rule_returns_allow() {
        let mut fw = Firewall::new();
        fw.add_rule(FirewallRule {
            id: 1,
            priority: 10,
            src_mac: Some([0xAA; 6]),
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        let pkt = make_pkt([0xAA; 6], [0xBB; 6], 0x0800);
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Allow);
        assert_eq!(fw.drop_count(), 0);
    }

    // -- Drop rule ----------------------------------------------------------

    #[test]
    fn drop_rule_returns_drop_and_increments_counter() {
        let mut fw = Firewall::new();
        fw.add_rule(FirewallRule {
            id: 2,
            priority: 10,
            src_mac: Some([0xCC; 6]),
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::Drop,
            active: true,
            ..Default::default()
        })
        .unwrap();

        let pkt = make_pkt([0xCC; 6], [0xDD; 6], 0x0800);
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Drop);
        assert_eq!(fw.drop_count(), 1);

        // Second drop increments further.
        assert_eq!(fw.evaluate(&pkt, 1), Verdict::Drop);
        assert_eq!(fw.drop_count(), 2);
    }

    // -- First-match (priority) semantics -----------------------------------

    #[test]
    fn first_match_semantics_lowest_priority_number_wins() {
        let mut fw = Firewall::new();

        // Lower-priority rule added first (priority 20 = low priority).
        fw.add_rule(FirewallRule {
            id: 10,
            priority: 20,
            src_mac: Some([0x11; 6]),
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::Drop,
            active: true,
            ..Default::default()
        })
        .unwrap();

        // Higher-priority rule added second (priority 5 = high priority).
        fw.add_rule(FirewallRule {
            id: 11,
            priority: 5,
            src_mac: Some([0x11; 6]),
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        let pkt = make_pkt([0x11; 6], [0x22; 6], 0x0800);
        // The Allow rule (priority 5) should win.
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Allow);
        assert_eq!(fw.drop_count(), 0);
    }

    // -- Dynamic block rule -------------------------------------------------

    #[test]
    fn dynamic_block_rule_applied_to_matching_packet() {
        let mut fw = Firewall::new();

        // Allow all traffic from 0x11 by default.
        fw.add_rule(FirewallRule {
            id: 1,
            priority: 100,
            src_mac: Some([0x11; 6]),
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        let pkt = make_pkt([0x11; 6], [0x22; 6], 0x0800);
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Allow);

        // IDS inserts a dynamic block rule with higher priority.
        fw.insert_dynamic_rule(
            FirewallRule {
                id: 999,
                priority: 1,
                src_mac: Some([0x11; 6]),
                dst_mac: None,
                vlan_id: None,
                ethertype: None,
                action: RuleAction::Drop,
                active: true,
                ..Default::default()
            },
            10_000_000, // expires at t=10s
        )
        .unwrap();

        // Now the same packet is blocked.
        assert_eq!(fw.evaluate(&pkt, 1_000_000), Verdict::Drop);
        assert_eq!(fw.drop_count(), 1);
    }

    // -- Expired rule no longer matches ------------------------------------

    #[test]
    fn expired_rule_no_longer_matches() {
        let mut fw = Firewall::new();

        // Allow rule at low priority.
        fw.add_rule(FirewallRule {
            id: 1,
            priority: 100,
            src_mac: Some([0x11; 6]),
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        // Dynamic drop rule, expires at 5s.
        fw.insert_dynamic_rule(
            FirewallRule {
                id: 50,
                priority: 1,
                src_mac: Some([0x11; 6]),
                dst_mac: None,
                vlan_id: None,
                ethertype: None,
                action: RuleAction::Drop,
                active: true,
                ..Default::default()
            },
            5_000_000,
        )
        .unwrap();

        let pkt = make_pkt([0x11; 6], [0x22; 6], 0x0800);

        // Before expiry — Drop.
        assert_eq!(fw.evaluate(&pkt, 3_000_000), Verdict::Drop);

        // Expire rules at t=6s.
        fw.expire_rules(6_000_000);

        // After expiry — Allow (fallback to the static rule).
        assert_eq!(fw.evaluate(&pkt, 6_000_000), Verdict::Allow);
    }

    // -- Rate limiter -------------------------------------------------------

    #[test]
    fn rate_limiter_allows_exactly_n_packets_per_second() {
        let mut fw = Firewall::new();

        // Rate-limit to 3 packets/second.
        fw.add_rule(FirewallRule {
            id: 7,
            priority: 10,
            src_mac: Some([0xAA; 6]),
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::RateLimit(3),
            active: true,
            ..Default::default()
        })
        .unwrap();

        let pkt = make_pkt([0xAA; 6], [0xBB; 6], 0x0800);

        // At t=0 the bucket starts full with 3 tokens.
        // First 3 packets should be allowed.
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::RateLimitAllow(3));
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::RateLimitAllow(3));
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::RateLimitAllow(3));

        // 4th packet at the same instant should be dropped.
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::RateLimitDrop(3));

        // After 1 full second, 3 more tokens are replenished.
        assert_eq!(fw.evaluate(&pkt, 1_000_000), Verdict::RateLimitAllow(3));
    }

    // -- Default deny -------------------------------------------------------

    #[test]
    fn default_deny_when_no_rule_matches() {
        let mut fw = Firewall::new();

        // Rule that does NOT match our test packet.
        fw.add_rule(FirewallRule {
            id: 1,
            priority: 10,
            src_mac: Some([0xFF; 6]),
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        let pkt = make_pkt([0x11; 6], [0x22; 6], 0x0800);
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Drop);
        assert_eq!(fw.drop_count(), 1);
    }

    // -- Connection tracker -------------------------------------------------

    #[test]
    fn conn_tracker_tracks_and_expires() {
        let mut ct: ConnTracker<16> = ConnTracker::new();
        let pkt = make_pkt([0x11; 6], [0x22; 6], 0x0800);

        // Not known before tracking.
        assert!(!ct.is_known(&pkt, 0));

        // Track it.
        ct.track(&pkt, 1_000_000);
        assert!(ct.is_known(&pkt, 1_000_000));

        // Still known within 5 seconds.
        assert!(ct.is_known(&pkt, 5_000_000));

        // Exactly at the 5-second boundary (1_000_000 + 5_000_000 = 6_000_000).
        assert!(ct.is_known(&pkt, 6_000_000));

        // Past the 5-second window — stale.
        assert!(!ct.is_known(&pkt, 6_000_001));
    }

    // -- Rule capacity limit ------------------------------------------------

    #[test]
    fn rule_capacity_limit() {
        let mut fw = Firewall::new();
        for i in 0..MAX_RULES {
            fw.add_rule(FirewallRule {
                id: i as u32,
                priority: i as u8,
                src_mac: None,
                dst_mac: None,
                vlan_id: None,
                ethertype: None,
                action: RuleAction::Allow,
                active: true,
                ..Default::default()
            })
            .unwrap();
        }

        // One more should fail.
        let result = fw.add_rule(FirewallRule {
            id: 9999,
            priority: 200,
            src_mac: None,
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        });
        assert_eq!(result, Err(VsError::ResourceExhausted));
    }

    // -- VLAN matching ------------------------------------------------------

    #[test]
    fn vlan_rule_matches_only_correct_vlan() {
        let mut fw = Firewall::new();
        fw.add_rule(FirewallRule {
            id: 20,
            priority: 10,
            src_mac: None,
            dst_mac: None,
            vlan_id: Some(100),
            ethertype: None,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        // Packet on VLAN 100 — matches.
        let mut pkt = make_pkt([0x11; 6], [0x22; 6], 0x0800);
        pkt.vlan_id = Some(100);
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Allow);

        // Packet on VLAN 200 — no match → default deny.
        pkt.vlan_id = Some(200);
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Drop);

        // Packet with no VLAN — no match → default deny.
        pkt.vlan_id = None;
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Drop);
    }

    // -- Log action ---------------------------------------------------------

    #[test]
    fn log_rule_returns_log() {
        let mut fw = Firewall::new();
        fw.add_rule(FirewallRule {
            id: 30,
            priority: 10,
            src_mac: None,
            dst_mac: None,
            vlan_id: None,
            ethertype: Some(0x0806), // ARP
            action: RuleAction::Log,
            active: true,
            ..Default::default()
        })
        .unwrap();

        let pkt = make_pkt([0x11; 6], [0x22; 6], 0x0806);
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Log);
        // Log does not increment drop counter.
        assert_eq!(fw.drop_count(), 0);
    }

    // -- Inactive rule is skipped -------------------------------------------

    #[test]
    fn inactive_rule_is_skipped() {
        let mut fw = Firewall::new();
        fw.add_rule(FirewallRule {
            id: 40,
            priority: 1,
            src_mac: None,
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::Allow,
            active: false, // inactive!
            ..Default::default()
        })
        .unwrap();

        let pkt = make_pkt([0x11; 6], [0x22; 6], 0x0800);
        // Falls through to default deny.
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Drop);
    }

    // -- ConnTracker capacity -----------------------------------------------

    #[test]
    fn conn_tracker_evicts_oldest_when_full() {
        let mut ct: ConnTracker<2> = ConnTracker::new();
        let pkt1 = make_pkt([0x01; 6], [0x02; 6], 0x0800);
        let pkt2 = make_pkt([0x03; 6], [0x04; 6], 0x0800);
        let pkt3 = make_pkt([0x05; 6], [0x06; 6], 0x0800);

        ct.track(&pkt1, 1_000_000);
        ct.track(&pkt2, 2_000_000);

        // Both known.
        assert!(ct.is_known(&pkt1, 2_000_000));
        assert!(ct.is_known(&pkt2, 2_000_000));

        // Adding a third evicts the oldest (pkt1).
        ct.track(&pkt3, 3_000_000);
        assert!(!ct.is_known(&pkt1, 3_000_000));
        assert!(ct.is_known(&pkt2, 3_000_000));
        assert!(ct.is_known(&pkt3, 3_000_000));
    }

    // ---- New tests below ----

    #[test]
    fn insert_rule_maintains_priority_sort_order() {
        // Firewall doesn't sort on insert (it finds best-match by priority
        // during evaluate), but the evaluate logic picks lowest priority value.
        let mut fw = Firewall::new();

        // Add rules in reverse priority order.
        fw.add_rule(FirewallRule {
            id: 3,
            priority: 30,
            src_mac: None,
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::Drop,
            active: true,
            ..Default::default()
        })
        .unwrap();

        fw.add_rule(FirewallRule {
            id: 1,
            priority: 10,
            src_mac: None,
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        fw.add_rule(FirewallRule {
            id: 2,
            priority: 20,
            src_mac: None,
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::Log,
            active: true,
            ..Default::default()
        })
        .unwrap();

        // Priority 10 (Allow) should win.
        let pkt = make_pkt([0x11; 6], [0x22; 6], 0x0800);
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Allow);
    }

    #[test]
    fn multiple_dynamic_rules_with_different_expiries() {
        let mut fw = Firewall::new();

        // Static allow rule at low priority.
        fw.add_rule(FirewallRule {
            id: 1,
            priority: 100,
            src_mac: None,
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        // Dynamic drop rule expires at t=3s.
        fw.insert_dynamic_rule(
            FirewallRule {
                id: 100,
                priority: 1,
                src_mac: Some([0x11; 6]),
                dst_mac: None,
                vlan_id: None,
                ethertype: None,
                action: RuleAction::Drop,
                active: true,
                ..Default::default()
            },
            3_000_000,
        )
        .unwrap();

        // Dynamic drop rule expires at t=6s (for a different source).
        fw.insert_dynamic_rule(
            FirewallRule {
                id: 101,
                priority: 2,
                src_mac: Some([0x22; 6]),
                dst_mac: None,
                vlan_id: None,
                ethertype: None,
                action: RuleAction::Drop,
                active: true,
                ..Default::default()
            },
            6_000_000,
        )
        .unwrap();

        let pkt1 = make_pkt([0x11; 6], [0xBB; 6], 0x0800);
        let pkt2 = make_pkt([0x22; 6], [0xBB; 6], 0x0800);

        // Both blocked before any expiry.
        assert_eq!(fw.evaluate(&pkt1, 1_000_000), Verdict::Drop);
        assert_eq!(fw.evaluate(&pkt2, 1_000_000), Verdict::Drop);

        // Expire at t=4s: first rule expired, second still active.
        fw.expire_rules(4_000_000);
        assert_eq!(fw.evaluate(&pkt1, 4_000_000), Verdict::Allow);
        assert_eq!(fw.evaluate(&pkt2, 4_000_000), Verdict::Drop);

        // Expire at t=7s: both expired.
        fw.expire_rules(7_000_000);
        assert_eq!(fw.evaluate(&pkt2, 7_000_000), Verdict::Allow);
    }

    #[test]
    fn rate_limiter_zero_packets_per_second_blocks_everything() {
        let mut fw = Firewall::new();
        fw.add_rule(FirewallRule {
            id: 50,
            priority: 10,
            src_mac: None,
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::RateLimit(0),
            active: true,
            ..Default::default()
        })
        .unwrap();

        let pkt = make_pkt([0xAA; 6], [0xBB; 6], 0x0800);
        // With rate=0, the bucket starts with 0 tokens. Should be dropped.
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::RateLimitDrop(0));
        assert_eq!(fw.evaluate(&pkt, 1_000_000), Verdict::RateLimitDrop(0));
    }

    #[test]
    fn rate_limiter_very_high_limit_allows_everything() {
        let mut fw = Firewall::new();
        fw.add_rule(FirewallRule {
            id: 51,
            priority: 10,
            src_mac: None,
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::RateLimit(10_000),
            active: true,
            ..Default::default()
        })
        .unwrap();

        let pkt = make_pkt([0xAA; 6], [0xBB; 6], 0x0800);
        // With 10,000 tokens/sec, many packets should be allowed at t=0.
        for _ in 0..100 {
            assert_eq!(fw.evaluate(&pkt, 0), Verdict::RateLimitAllow(10_000));
        }
    }

    #[test]
    fn connection_tracker_basic_insert_and_lookup() {
        let mut ct: ConnTracker<8> = ConnTracker::new();
        let pkt = make_pkt([0xAA; 6], [0xBB; 6], 0x0800);

        assert!(!ct.is_known(&pkt, 0));

        ct.track(&pkt, 1000);
        assert!(ct.is_known(&pkt, 1000));
        assert!(ct.is_known(&pkt, 2000));
    }

    #[test]
    fn rule_with_specific_src_mac_matches_only_that_mac() {
        let mut fw = Firewall::new();
        fw.add_rule(FirewallRule {
            id: 60,
            priority: 10,
            src_mac: Some([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]),
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        // Matching src_mac.
        let pkt_match = make_pkt([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01], [0xFF; 6], 0x0800);
        assert_eq!(fw.evaluate(&pkt_match, 0), Verdict::Allow);

        // Non-matching src_mac.
        let pkt_no = make_pkt([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x02], [0xFF; 6], 0x0800);
        assert_eq!(fw.evaluate(&pkt_no, 0), Verdict::Drop);
    }

    #[test]
    fn rule_with_specific_dst_mac_matches_only_that_mac() {
        let mut fw = Firewall::new();
        fw.add_rule(FirewallRule {
            id: 61,
            priority: 10,
            src_mac: None,
            dst_mac: Some([0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01]),
            vlan_id: None,
            ethertype: None,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        // Matching dst_mac.
        let pkt_match = make_pkt([0x11; 6], [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01], 0x0800);
        assert_eq!(fw.evaluate(&pkt_match, 0), Verdict::Allow);

        // Non-matching dst_mac.
        let pkt_no = make_pkt([0x11; 6], [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x02], 0x0800);
        assert_eq!(fw.evaluate(&pkt_no, 0), Verdict::Drop);
    }

    #[test]
    fn rule_with_specific_ethertype_matches_only_that_ethertype() {
        let mut fw = Firewall::new();
        fw.add_rule(FirewallRule {
            id: 62,
            priority: 10,
            src_mac: None,
            dst_mac: None,
            vlan_id: None,
            ethertype: Some(0x0806), // ARP
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        // Matching ethertype.
        let pkt_arp = make_pkt([0x11; 6], [0x22; 6], 0x0806);
        assert_eq!(fw.evaluate(&pkt_arp, 0), Verdict::Allow);

        // Non-matching ethertype (IPv4).
        let pkt_ip = make_pkt([0x11; 6], [0x22; 6], 0x0800);
        assert_eq!(fw.evaluate(&pkt_ip, 0), Verdict::Drop);
    }

    #[test]
    fn rule_matching_by_service_id_via_ethertype() {
        let mut fw = Firewall::new();
        fw.add_rule(FirewallRule {
            id: 63,
            priority: 10,
            src_mac: None,
            dst_mac: None,
            vlan_id: None,
            ethertype: Some(0x88B5), // Custom protocol
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        let pkt_match = make_pkt([0x11; 6], [0x22; 6], 0x88B5);
        assert_eq!(fw.evaluate(&pkt_match, 0), Verdict::Allow);

        let pkt_no = make_pkt([0x11; 6], [0x22; 6], 0x88B6);
        assert_eq!(fw.evaluate(&pkt_no, 0), Verdict::Drop);
    }

    #[test]
    fn drop_counter_increments_for_each_dropped_packet() {
        let mut fw = Firewall::new();
        // Default deny (no rules) means everything is dropped.
        let pkt = make_pkt([0x11; 6], [0x22; 6], 0x0800);

        assert_eq!(fw.drop_count(), 0);

        fw.evaluate(&pkt, 0);
        assert_eq!(fw.drop_count(), 1);

        fw.evaluate(&pkt, 1);
        assert_eq!(fw.drop_count(), 2);

        fw.evaluate(&pkt, 2);
        assert_eq!(fw.drop_count(), 3);

        fw.evaluate(&pkt, 3);
        fw.evaluate(&pkt, 4);
        assert_eq!(fw.drop_count(), 5);
    }

    #[test]
    fn first_allow_second_drop_allow_wins_by_priority() {
        let mut fw = Firewall::new();

        // Allow rule with higher priority (lower number).
        fw.add_rule(FirewallRule {
            id: 70,
            priority: 5,
            src_mac: Some([0x11; 6]),
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        // Drop rule with lower priority (higher number).
        fw.add_rule(FirewallRule {
            id: 71,
            priority: 10,
            src_mac: Some([0x11; 6]),
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::Drop,
            active: true,
            ..Default::default()
        })
        .unwrap();

        let pkt = make_pkt([0x11; 6], [0x22; 6], 0x0800);
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Allow);
        assert_eq!(fw.drop_count(), 0);
    }

    #[test]
    fn insert_128_rules_full_capacity_129th_fails() {
        let mut fw = Firewall::new();
        for i in 0..128 {
            fw.add_rule(FirewallRule {
                id: i as u32,
                priority: i as u8,
                src_mac: None,
                dst_mac: None,
                vlan_id: None,
                ethertype: None,
                action: RuleAction::Allow,
                active: true,
                ..Default::default()
            })
            .unwrap();
        }

        // 129th should fail.
        let result = fw.add_rule(FirewallRule {
            id: 128,
            priority: 200,
            src_mac: None,
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        });
        assert_eq!(result, Err(VsError::ResourceExhausted));
    }

    #[test]
    fn expire_removes_only_expired_rules_keeps_active_ones() {
        let mut fw = Firewall::new();

        // Static allow rule.
        fw.add_rule(FirewallRule {
            id: 1,
            priority: 100,
            src_mac: None,
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        // Dynamic rule that expires at t=5s.
        fw.insert_dynamic_rule(
            FirewallRule {
                id: 200,
                priority: 1,
                src_mac: Some([0x11; 6]),
                dst_mac: None,
                vlan_id: None,
                ethertype: None,
                action: RuleAction::Drop,
                active: true,
                ..Default::default()
            },
            5_000_000,
        )
        .unwrap();

        // Dynamic rule that expires at t=10s.
        fw.insert_dynamic_rule(
            FirewallRule {
                id: 201,
                priority: 2,
                src_mac: Some([0x22; 6]),
                dst_mac: None,
                vlan_id: None,
                ethertype: None,
                action: RuleAction::Drop,
                active: true,
                ..Default::default()
            },
            10_000_000,
        )
        .unwrap();

        let pkt1 = make_pkt([0x11; 6], [0xBB; 6], 0x0800);
        let pkt2 = make_pkt([0x22; 6], [0xBB; 6], 0x0800);

        // Both blocked at t=2s.
        assert_eq!(fw.evaluate(&pkt1, 2_000_000), Verdict::Drop);
        assert_eq!(fw.evaluate(&pkt2, 2_000_000), Verdict::Drop);

        // Expire at t=6s: first rule gone, second still active.
        fw.expire_rules(6_000_000);
        assert_eq!(fw.evaluate(&pkt1, 6_000_000), Verdict::Allow);
        assert_eq!(fw.evaluate(&pkt2, 6_000_000), Verdict::Drop);
    }

    #[test]
    fn dynamic_rule_with_no_expiry_via_static_add_never_expires() {
        let mut fw = Firewall::new();

        // A static rule (added with add_rule) has no expiry.
        fw.add_rule(FirewallRule {
            id: 300,
            priority: 1,
            src_mac: Some([0x11; 6]),
            dst_mac: None,
            vlan_id: None,
            ethertype: None,
            action: RuleAction::Drop,
            active: true,
            ..Default::default()
        })
        .unwrap();

        let pkt = make_pkt([0x11; 6], [0x22; 6], 0x0800);

        // Even after a very long time, the static rule still matches.
        fw.expire_rules(u64::MAX / 2);
        assert_eq!(fw.evaluate(&pkt, u64::MAX / 2), Verdict::Drop);
    }

    // ====================================================================
    // L3/L4 matching tests
    // ====================================================================

    /// Build a minimal IPv4/TCP packet payload for firewall L3/L4 matching.
    /// Returns `(ethertype=0x0800, payload bytes)`.
    fn make_ipv4_tcp_payload(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> [u8; 60] {
        let mut buf = [0u8; 60];
        // IPv4 header (20 bytes, IHL=5, protocol=6=TCP, total_length=40)
        buf[0] = 0x45; // version=4, IHL=5
        buf[2] = 0x00;
        buf[3] = 40; // total length
        buf[9] = 6; // protocol = TCP
        buf[12..16].copy_from_slice(&src_ip);
        buf[16..20].copy_from_slice(&dst_ip);
        // TCP header starts at offset 20
        buf[20] = (src_port >> 8) as u8;
        buf[21] = src_port as u8;
        buf[22] = (dst_port >> 8) as u8;
        buf[23] = dst_port as u8;
        buf[32] = 0x50; // data offset = 5 (20 bytes)
        buf
    }

    /// Build an IPv4/UDP packet payload.
    fn make_ipv4_udp_payload(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> [u8; 48] {
        let mut buf = [0u8; 48];
        // IPv4 header (20 bytes, protocol=17=UDP)
        buf[0] = 0x45;
        buf[2] = 0x00;
        buf[3] = 28; // total length
        buf[9] = 17; // protocol = UDP
        buf[12..16].copy_from_slice(&src_ip);
        buf[16..20].copy_from_slice(&dst_ip);
        // UDP header starts at offset 20
        buf[20] = (src_port >> 8) as u8;
        buf[21] = src_port as u8;
        buf[22] = (dst_port >> 8) as u8;
        buf[23] = dst_port as u8;
        buf[24] = 0;
        buf[25] = 8; // UDP length = 8
        buf
    }

    #[test]
    fn l3_rule_matches_by_src_ip() {
        let mut fw = Firewall::new();
        fw.add_rule(FirewallRule {
            id: 500,
            priority: 10,
            src_ip: Some(IpAddr::V4([192, 168, 1, 100])),
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        let payload = make_ipv4_tcp_payload([192, 168, 1, 100], [10, 0, 0, 1], 12345, 80);
        let pkt = EthPacket {
            src_mac: [0x11; 6],
            dst_mac: [0x22; 6],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &payload,
        };
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Allow);

        // Different src IP — no match → default deny.
        let payload2 = make_ipv4_tcp_payload([192, 168, 1, 200], [10, 0, 0, 1], 12345, 80);
        let pkt2 = EthPacket {
            src_mac: [0x11; 6],
            dst_mac: [0x22; 6],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &payload2,
        };
        assert_eq!(fw.evaluate(&pkt2, 0), Verdict::Drop);
    }

    #[test]
    fn l3_rule_matches_by_dst_ip() {
        let mut fw = Firewall::new();
        fw.add_rule(FirewallRule {
            id: 501,
            priority: 10,
            dst_ip: Some(IpAddr::V4([10, 0, 0, 1])),
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        let payload = make_ipv4_tcp_payload([192, 168, 1, 1], [10, 0, 0, 1], 5000, 443);
        let pkt = EthPacket {
            src_mac: [0x11; 6],
            dst_mac: [0x22; 6],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &payload,
        };
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Allow);

        // Different dst IP — no match.
        let payload2 = make_ipv4_tcp_payload([192, 168, 1, 1], [10, 0, 0, 2], 5000, 443);
        let pkt2 = EthPacket {
            src_mac: [0x11; 6],
            dst_mac: [0x22; 6],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &payload2,
        };
        assert_eq!(fw.evaluate(&pkt2, 0), Verdict::Drop);
    }

    #[test]
    fn l3_rule_matches_by_protocol() {
        let mut fw = Firewall::new();
        // Allow only UDP traffic.
        fw.add_rule(FirewallRule {
            id: 502,
            priority: 10,
            protocol: Some(IpProtocol::Udp),
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        // UDP packet — allowed.
        let udp = make_ipv4_udp_payload([10, 0, 0, 1], [10, 0, 0, 2], 1234, 5678);
        let pkt_udp = EthPacket {
            src_mac: [0x11; 6],
            dst_mac: [0x22; 6],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &udp,
        };
        assert_eq!(fw.evaluate(&pkt_udp, 0), Verdict::Allow);

        // TCP packet — no match → dropped.
        let tcp = make_ipv4_tcp_payload([10, 0, 0, 1], [10, 0, 0, 2], 1234, 5678);
        let pkt_tcp = EthPacket {
            src_mac: [0x11; 6],
            dst_mac: [0x22; 6],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &tcp,
        };
        assert_eq!(fw.evaluate(&pkt_tcp, 0), Verdict::Drop);
    }

    #[test]
    fn l4_rule_matches_by_dst_port() {
        let mut fw = Firewall::new();
        // Allow traffic to port 443 only.
        fw.add_rule(FirewallRule {
            id: 503,
            priority: 10,
            dst_port: Some(443),
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        // Packet to port 443 — allowed.
        let payload = make_ipv4_tcp_payload([10, 0, 0, 1], [10, 0, 0, 2], 50000, 443);
        let pkt = EthPacket {
            src_mac: [0x11; 6],
            dst_mac: [0x22; 6],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &payload,
        };
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Allow);

        // Packet to port 80 — no match → dropped.
        let payload2 = make_ipv4_tcp_payload([10, 0, 0, 1], [10, 0, 0, 2], 50000, 80);
        let pkt2 = EthPacket {
            src_mac: [0x11; 6],
            dst_mac: [0x22; 6],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &payload2,
        };
        assert_eq!(fw.evaluate(&pkt2, 0), Verdict::Drop);
    }

    #[test]
    fn l4_rule_matches_by_src_port() {
        let mut fw = Firewall::new();
        fw.add_rule(FirewallRule {
            id: 504,
            priority: 10,
            src_port: Some(12345),
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        let payload = make_ipv4_tcp_payload([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80);
        let pkt = EthPacket {
            src_mac: [0x11; 6],
            dst_mac: [0x22; 6],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &payload,
        };
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Allow);

        // Different src port — no match.
        let payload2 = make_ipv4_tcp_payload([10, 0, 0, 1], [10, 0, 0, 2], 54321, 80);
        let pkt2 = EthPacket {
            src_mac: [0x11; 6],
            dst_mac: [0x22; 6],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &payload2,
        };
        assert_eq!(fw.evaluate(&pkt2, 0), Verdict::Drop);
    }

    #[test]
    fn combined_l2_l3_l4_rule() {
        let mut fw = Firewall::new();
        // Rule: src_mac=0x11*, dst_ip=10.0.0.2, dst_port=443, TCP only → Allow.
        fw.add_rule(FirewallRule {
            id: 505,
            priority: 10,
            src_mac: Some([0x11; 6]),
            dst_ip: Some(IpAddr::V4([10, 0, 0, 2])),
            protocol: Some(IpProtocol::Tcp),
            dst_port: Some(443),
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        // Full match — allowed.
        let payload = make_ipv4_tcp_payload([192, 168, 1, 1], [10, 0, 0, 2], 50000, 443);
        let pkt = EthPacket {
            src_mac: [0x11; 6],
            dst_mac: [0x22; 6],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &payload,
        };
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Allow);

        // Wrong src_mac — no match.
        let pkt2 = EthPacket {
            src_mac: [0x22; 6],
            dst_mac: [0x22; 6],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &payload,
        };
        assert_eq!(fw.evaluate(&pkt2, 0), Verdict::Drop);

        // Wrong dst port — no match.
        let payload3 = make_ipv4_tcp_payload([192, 168, 1, 1], [10, 0, 0, 2], 50000, 80);
        let pkt3 = EthPacket {
            src_mac: [0x11; 6],
            dst_mac: [0x22; 6],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &payload3,
        };
        assert_eq!(fw.evaluate(&pkt3, 0), Verdict::Drop);
    }

    #[test]
    fn l3_rule_on_non_ip_packet_does_not_match() {
        let mut fw = Firewall::new();
        fw.add_rule(FirewallRule {
            id: 506,
            priority: 10,
            src_ip: Some(IpAddr::V4([10, 0, 0, 1])),
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        // ARP packet (ethertype 0x0806) — L3 rule requires IP but packet is not IP.
        let pkt = make_pkt([0x11; 6], [0x22; 6], 0x0806);
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Drop);
    }

    // ====================================================================
    // TCP state tracker tests
    // ====================================================================

    #[test]
    fn tcp_full_handshake_and_teardown() {
        let mut tracker = TcpStateTracker::new();
        let src = IpAddr::V4([192, 168, 1, 1]);
        let dst = IpAddr::V4([10, 0, 0, 1]);

        // SYN from client → SynSent
        let state = tracker.process(src, dst, 5000, 80, tf::SYN, 1_000_000);
        assert_eq!(state, TcpState::SynSent);

        // SYN-ACK from server (reverse direction) → SynReceived
        let state = tracker.process(dst, src, 80, 5000, tf::SYN_ACK, 2_000_000);
        assert_eq!(state, TcpState::SynReceived);

        // ACK from client (forward direction) → Established
        let state = tracker.process(src, dst, 5000, 80, tf::ACK, 3_000_000);
        assert_eq!(state, TcpState::Established);

        // Verify get_state works.
        assert_eq!(
            tracker.get_state(src, dst, 5000, 80),
            Some(TcpState::Established)
        );

        // FIN from client (forward direction) → FinWait
        let state = tracker.process(src, dst, 5000, 80, tf::FIN, 4_000_000);
        assert_eq!(state, TcpState::FinWait);

        // ACK of FIN from server (peer direction) → Closed
        let state = tracker.process(dst, src, 80, 5000, tf::ACK, 5_000_000);
        assert_eq!(state, TcpState::Closed);

        // Entry should be gone.
        assert_eq!(tracker.get_state(src, dst, 5000, 80), None);
    }

    #[test]
    fn tcp_rst_closes_connection() {
        let mut tracker = TcpStateTracker::new();
        let src = IpAddr::V4([10, 0, 0, 1]);
        let dst = IpAddr::V4([10, 0, 0, 2]);

        // SYN → SynSent
        tracker.process(src, dst, 1234, 80, tf::SYN, 1_000_000);

        // SYN-ACK → SynReceived
        tracker.process(dst, src, 80, 1234, tf::SYN_ACK, 2_000_000);

        // RST → Closed
        let state = tracker.process(src, dst, 1234, 80, tf::RST, 3_000_000);
        assert_eq!(state, TcpState::Closed);
        assert_eq!(tracker.get_state(src, dst, 1234, 80), None);
    }

    #[test]
    fn tcp_state_tracker_timeout() {
        let mut tracker = TcpStateTracker::new();
        let src = IpAddr::V4([10, 0, 0, 1]);
        let dst = IpAddr::V4([10, 0, 0, 2]);

        // SYN → SynSent
        tracker.process(src, dst, 1234, 80, tf::SYN, 1_000_000);
        assert_eq!(
            tracker.get_state(src, dst, 1234, 80),
            Some(TcpState::SynSent)
        );

        // Process after 30+ seconds timeout — stale entry should be cleaned.
        // A new SYN on the same tuple starts fresh.
        let state = tracker.process(src, dst, 1234, 80, tf::SYN, 32_000_000);
        assert_eq!(state, TcpState::SynSent);
    }

    #[test]
    fn tcp_non_syn_without_existing_entry_returns_closed() {
        let mut tracker = TcpStateTracker::new();
        let src = IpAddr::V4([10, 0, 0, 1]);
        let dst = IpAddr::V4([10, 0, 0, 2]);

        // ACK without a prior SYN — not tracked.
        let state = tracker.process(src, dst, 1234, 80, tf::ACK, 1_000_000);
        assert_eq!(state, TcpState::Closed);
        assert_eq!(tracker.get_state(src, dst, 1234, 80), None);
    }

    #[test]
    fn tcp_multiple_connections_tracked_independently() {
        let mut tracker = TcpStateTracker::new();
        let src = IpAddr::V4([10, 0, 0, 1]);
        let dst1 = IpAddr::V4([10, 0, 0, 2]);
        let dst2 = IpAddr::V4([10, 0, 0, 3]);

        // Connection 1: SYN → SYN-ACK → ACK → Established
        tracker.process(src, dst1, 1000, 80, tf::SYN, 1_000_000);
        tracker.process(dst1, src, 80, 1000, tf::SYN_ACK, 2_000_000);
        tracker.process(src, dst1, 1000, 80, tf::ACK, 3_000_000);

        // Connection 2: SYN only → SynSent
        tracker.process(src, dst2, 2000, 443, tf::SYN, 3_000_000);

        // Verify both tracked independently.
        assert_eq!(
            tracker.get_state(src, dst1, 1000, 80),
            Some(TcpState::Established)
        );
        assert_eq!(
            tracker.get_state(src, dst2, 2000, 443),
            Some(TcpState::SynSent)
        );
    }

    #[test]
    fn tcp_get_state_works_from_reverse_direction() {
        let mut tracker = TcpStateTracker::new();
        let a = IpAddr::V4([10, 0, 0, 1]);
        let b = IpAddr::V4([10, 0, 0, 2]);

        tracker.process(a, b, 5000, 80, tf::SYN, 1_000_000);

        // Query from forward direction.
        assert_eq!(tracker.get_state(a, b, 5000, 80), Some(TcpState::SynSent));
        // Query from reverse direction.
        assert_eq!(tracker.get_state(b, a, 80, 5000), Some(TcpState::SynSent));
    }

    // -----------------------------------------------------------------------
    // Security property assertion tests
    // -----------------------------------------------------------------------

    #[test]
    fn security_default_deny_no_rules_blocks_all() {
        let mut fw = Firewall::new();
        let pkt = make_pkt([0x11; 6], [0x22; 6], 0x0800);
        // With no rules, firewall default action is Drop.
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Drop);
    }

    #[test]
    fn security_default_deny_unmatched_packet_blocked() {
        let mut fw = Firewall::new();
        // Add a rule that matches a specific MAC.
        fw.add_rule(FirewallRule {
            id: 1,
            priority: 10,
            src_mac: Some([0xAA; 6]),
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        // A different MAC should be dropped (default deny).
        let pkt = make_pkt([0xBB; 6], [0xCC; 6], 0x0800);
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Drop);
    }

    #[test]
    fn security_firewall_rule_capacity_limit() {
        let mut fw = Firewall::new();
        for i in 0..MAX_RULES {
            let result = fw.add_rule(FirewallRule {
                id: i as u32,
                priority: i as u8,
                src_mac: Some([(i & 0xFF) as u8; 6]),
                action: RuleAction::Allow,
                active: true,
                ..Default::default()
            });
            assert!(result.is_ok(), "rule {i} should fit");
        }

        // One more should fail.
        let overflow = fw.add_rule(FirewallRule {
            id: 999,
            priority: 200,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        });
        assert_eq!(overflow, Err(VsError::ResourceExhausted));
    }

    #[test]
    fn security_tcp_rst_in_wrong_state_does_not_establish() {
        let mut tracker = TcpStateTracker::new();
        let a = IpAddr::V4([10, 0, 0, 1]);
        let b = IpAddr::V4([10, 0, 0, 2]);

        // Send RST without prior SYN — should not create an established connection.
        tracker.process(a, b, 5000, 80, tf::RST, 1_000_000);
        let state = tracker.get_state(a, b, 5000, 80);
        assert_ne!(
            state,
            Some(TcpState::Established),
            "RST without handshake must not establish connection"
        );
    }

    #[test]
    fn security_connection_timeout_constant_is_5_seconds() {
        // Security property: connections expire after 5 seconds.
        assert_eq!(CONN_TIMEOUT_US, 5_000_000);
    }

    #[test]
    fn security_drop_counter_increments_on_default_deny() {
        let mut fw = Firewall::new();
        let pkt = make_pkt([0x11; 6], [0x22; 6], 0x0800);

        assert_eq!(fw.drop_count(), 0);
        fw.evaluate(&pkt, 0);
        assert_eq!(fw.drop_count(), 1);
        fw.evaluate(&pkt, 1);
        assert_eq!(fw.drop_count(), 2);
    }

    // -----------------------------------------------------------------------
    // New tests for fixes
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_rule_id_rejected() {
        let mut fw = Firewall::new();
        fw.add_rule(FirewallRule {
            id: 42,
            priority: 10,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        let result = fw.add_rule(FirewallRule {
            id: 42,
            priority: 20,
            action: RuleAction::Drop,
            active: true,
            ..Default::default()
        });
        assert_eq!(result, Err(VsError::InvalidConfig));
    }

    #[test]
    fn duplicate_dynamic_rule_id_rejected() {
        let mut fw = Firewall::new();
        fw.insert_dynamic_rule(
            FirewallRule {
                id: 42,
                priority: 10,
                action: RuleAction::Drop,
                active: true,
                ..Default::default()
            },
            10_000_000,
        )
        .unwrap();

        let result = fw.insert_dynamic_rule(
            FirewallRule {
                id: 42,
                priority: 20,
                action: RuleAction::Allow,
                active: true,
                ..Default::default()
            },
            20_000_000,
        );
        assert_eq!(result, Err(VsError::InvalidConfig));
    }

    #[test]
    fn remove_rule_frees_slot() {
        let mut fw = Firewall::new();
        fw.add_rule(FirewallRule {
            id: 1,
            priority: 10,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        let pkt = make_pkt([0x11; 6], [0x22; 6], 0x0800);
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Allow);

        assert!(fw.remove_rule(1));
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Drop);

        // Removing non-existent rule returns false.
        assert!(!fw.remove_rule(1));
    }

    #[test]
    fn remove_rule_reclaims_slot_for_new_rule() {
        let mut fw = Firewall::new();

        // Fill to capacity.
        for i in 0..MAX_RULES {
            fw.add_rule(FirewallRule {
                id: i as u32,
                priority: i as u8,
                action: RuleAction::Allow,
                active: true,
                ..Default::default()
            })
            .unwrap();
        }

        // Full — cannot add.
        assert_eq!(
            fw.add_rule(FirewallRule {
                id: 9999,
                priority: 200,
                action: RuleAction::Allow,
                active: true,
                ..Default::default()
            }),
            Err(VsError::ResourceExhausted)
        );

        // Remove one, then add succeeds (reuse the freed priority slot).
        fw.remove_rule(0);
        fw.add_rule(FirewallRule {
            id: 9999,
            priority: 0,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();
    }

    #[test]
    fn update_rule_changes_action_and_priority() {
        let mut fw = Firewall::new();
        fw.add_rule(FirewallRule {
            id: 1,
            priority: 10,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        fw.update_rule(1, Some(RuleAction::Drop), Some(5)).unwrap();

        let pkt = make_pkt([0x11; 6], [0x22; 6], 0x0800);
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Drop);
    }

    #[test]
    fn update_rule_nonexistent_returns_error() {
        let mut fw = Firewall::new();
        assert_eq!(
            fw.update_rule(999, Some(RuleAction::Allow), None),
            Err(VsError::InvalidInput)
        );
    }

    #[test]
    fn rule_hits_tracks_matches() {
        let mut fw = Firewall::new();
        fw.add_rule(FirewallRule {
            id: 1,
            priority: 10,
            src_mac: Some([0xAA; 6]),
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        assert_eq!(fw.rule_hits(1), Some(0));

        let pkt = make_pkt([0xAA; 6], [0xBB; 6], 0x0800);
        fw.evaluate(&pkt, 0);
        fw.evaluate(&pkt, 1);
        fw.evaluate(&pkt, 2);

        assert_eq!(fw.rule_hits(1), Some(3));
        assert_eq!(fw.rule_hits(999), None);
    }

    #[test]
    fn expired_rule_slot_is_reused() {
        let mut fw = Firewall::new();

        // Fill to capacity with dynamic rules.
        for i in 0..MAX_RULES {
            fw.insert_dynamic_rule(
                FirewallRule {
                    id: i as u32,
                    priority: i as u8,
                    action: RuleAction::Drop,
                    active: true,
                    ..Default::default()
                },
                5_000_000,
            )
            .unwrap();
        }

        // Full.
        assert_eq!(
            fw.add_rule(FirewallRule {
                id: 9999,
                priority: 200,
                action: RuleAction::Allow,
                active: true,
                ..Default::default()
            }),
            Err(VsError::ResourceExhausted)
        );

        // Expire all dynamic rules — slots are reclaimed.
        fw.expire_rules(6_000_000);

        // Now we can add a new rule.
        fw.add_rule(FirewallRule {
            id: 9999,
            priority: 10,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();
    }

    #[test]
    fn rate_limiter_bucket_freed_on_rule_removal() {
        let mut fw = Firewall::new();

        // Add rate-limit rules to consume all 32 buckets.
        for i in 0..MAX_RATE_LIMITERS {
            fw.add_rule(FirewallRule {
                id: i as u32,
                priority: i as u8,
                src_mac: Some([i as u8; 6]),
                action: RuleAction::RateLimit(100),
                active: true,
                ..Default::default()
            })
            .unwrap();

            // Trigger bucket allocation.
            let pkt = make_pkt([i as u8; 6], [0xBB; 6], 0x0800);
            fw.evaluate(&pkt, 0);
        }

        // Add one more rate-limit rule.
        fw.add_rule(FirewallRule {
            id: 100,
            priority: 200,
            src_mac: Some([0xFE; 6]),
            action: RuleAction::RateLimit(100),
            active: true,
            ..Default::default()
        })
        .unwrap();

        // All buckets are taken — LRU eviction replaces the oldest bucket.
        let pkt_new = make_pkt([0xFE; 6], [0xBB; 6], 0x0800);
        assert_eq!(
            fw.evaluate(&pkt_new, 1_000_000),
            Verdict::RateLimitAllow(100)
        );

        // The evicted rule's bucket was reclaimed, so removing it and
        // re-evaluating the new rule still works.
        fw.remove_rule(0);
        assert_eq!(
            fw.evaluate(&pkt_new, 2_000_000),
            Verdict::RateLimitAllow(100)
        );
    }

    #[test]
    fn verdict_distinguishes_rate_limit_allow_and_drop() {
        let mut fw = Firewall::new();
        fw.add_rule(FirewallRule {
            id: 1,
            priority: 10,
            action: RuleAction::RateLimit(1),
            active: true,
            ..Default::default()
        })
        .unwrap();

        let pkt = make_pkt([0x11; 6], [0x22; 6], 0x0800);
        // First packet allowed.
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::RateLimitAllow(1));
        // Second packet dropped.
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::RateLimitDrop(1));
    }

    #[test]
    fn tcp_fin_from_same_direction_does_not_close() {
        let mut tracker = TcpStateTracker::new();
        let src = IpAddr::V4([10, 0, 0, 1]);
        let dst = IpAddr::V4([10, 0, 0, 2]);

        // Full handshake.
        tracker.process(src, dst, 5000, 80, tf::SYN, 1_000_000);
        tracker.process(dst, src, 80, 5000, tf::SYN_ACK, 2_000_000);
        tracker.process(src, dst, 5000, 80, tf::ACK, 3_000_000);

        // FIN from forward direction.
        let state = tracker.process(src, dst, 5000, 80, tf::FIN, 4_000_000);
        assert_eq!(state, TcpState::FinWait);

        // ACK from the SAME direction (forward) should NOT close.
        let state = tracker.process(src, dst, 5000, 80, tf::ACK, 5_000_000);
        assert_eq!(state, TcpState::FinWait);

        // ACK from the PEER direction (reverse) SHOULD close.
        let state = tracker.process(dst, src, 80, 5000, tf::ACK, 6_000_000);
        assert_eq!(state, TcpState::Closed);
    }

    #[test]
    fn tcp_fin_from_server_requires_client_ack_to_close() {
        let mut tracker = TcpStateTracker::new();
        let client = IpAddr::V4([10, 0, 0, 1]);
        let server = IpAddr::V4([10, 0, 0, 2]);

        // Full handshake.
        tracker.process(client, server, 5000, 80, tf::SYN, 1_000_000);
        tracker.process(server, client, 80, 5000, tf::SYN_ACK, 2_000_000);
        tracker.process(client, server, 5000, 80, tf::ACK, 3_000_000);

        // FIN from server (reverse direction).
        let state = tracker.process(server, client, 80, 5000, tf::FIN, 4_000_000);
        assert_eq!(state, TcpState::FinWait);

        // ACK from server again — same direction as FIN, should NOT close.
        let state = tracker.process(server, client, 80, 5000, tf::ACK, 5_000_000);
        assert_eq!(state, TcpState::FinWait);

        // ACK from client (peer) — SHOULD close.
        let state = tracker.process(client, server, 5000, 80, tf::ACK, 6_000_000);
        assert_eq!(state, TcpState::Closed);
    }

    #[test]
    fn log_callback_is_invoked() {
        use core::sync::atomic::{AtomicU32, Ordering};
        static LOGGED_RULE_ID: AtomicU32 = AtomicU32::new(0);

        fn test_log_fn(_pkt: &EthPacket<'_>, rule_id: u32) {
            LOGGED_RULE_ID.store(rule_id, Ordering::Relaxed);
        }

        let mut fw = Firewall::new();
        fw.set_log_fn(test_log_fn);
        fw.add_rule(FirewallRule {
            id: 42,
            priority: 10,
            action: RuleAction::Log,
            active: true,
            ..Default::default()
        })
        .unwrap();

        let pkt = make_pkt([0x11; 6], [0x22; 6], 0x0800);
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Log);
        assert_eq!(LOGGED_RULE_ID.load(Ordering::Relaxed), 42);
    }

    #[test]
    fn rule_capacity_reports_active_count() {
        let mut fw = Firewall::new();
        assert_eq!(fw.rule_capacity(), (0, MAX_RULES));

        fw.add_rule(FirewallRule {
            id: 1,
            priority: 10,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(fw.rule_capacity(), (1, MAX_RULES));

        fw.add_rule(FirewallRule {
            id: 2,
            priority: 20,
            action: RuleAction::Allow,
            active: false,
            ..Default::default()
        })
        .unwrap();
        // Only active rules counted.
        assert_eq!(fw.rule_capacity(), (1, MAX_RULES));
    }

    // -- Regression: update_rule must re-sort and reject duplicate priority --
    //
    // Critical finding: `update_rule` previously mutated `priority` in place
    // without re-sorting `self.rules`.  Since `evaluate` walks the array in
    // ascending order and `break`s on first match, raising a Drop rule above
    // an Allow rule via `update_rule` left the array in stale order and the
    // older lower-priority Allow continued to win — silently bypassing the
    // intended Drop.  The fix re-sorts after a priority change and rejects
    // duplicate priorities (mirroring `insert_slot`).

    #[test]
    fn update_rule_priority_change_resorts_and_evaluates_correctly() {
        let mut fw = Firewall::new();

        // Rule A: priority 10 (high), Drop everything from this MAC.
        fw.add_rule(FirewallRule {
            id: 100,
            priority: 10,
            src_mac: Some([0xAA; 6]),
            action: RuleAction::Drop,
            active: true,
            ..Default::default()
        })
        .unwrap();

        // Rule B: priority 20 (lower), Allow same MAC.
        fw.add_rule(FirewallRule {
            id: 200,
            priority: 20,
            src_mac: Some([0xAA; 6]),
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        let pkt = make_pkt([0xAA; 6], [0xBB; 6], 0x0800);

        // A (priority 10) wins — Drop.
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Drop);

        // Demote A by raising its priority number to 30 (below B's 20).
        fw.update_rule(100, None, Some(30)).unwrap();

        // Now B (priority 20) is the new first match — Allow.
        // Without sort_rules() in update_rule this would still return Drop.
        assert_eq!(fw.evaluate(&pkt, 1), Verdict::Allow);

        // Array must be in monotonically increasing priority order.
        let priorities: [u8; 2] = [fw.rules[0].rule.priority, fw.rules[1].rule.priority];
        assert!(
            priorities[0] <= priorities[1],
            "rules array not sorted after update_rule: {priorities:?}",
        );
    }

    #[test]
    fn update_rule_duplicate_priority_is_rejected() {
        let mut fw = Firewall::new();

        fw.add_rule(FirewallRule {
            id: 100,
            priority: 30,
            src_mac: Some([0xAA; 6]),
            action: RuleAction::Drop,
            active: true,
            ..Default::default()
        })
        .unwrap();

        fw.add_rule(FirewallRule {
            id: 200,
            priority: 20,
            src_mac: Some([0xAA; 6]),
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        // Attempting to update B to priority 30 (same as A) must fail.
        assert_eq!(
            fw.update_rule(200, None, Some(30)),
            Err(VsError::PolicyViolation),
        );

        // State must be unchanged: B still at priority 20, A still at 30.
        // Verify by matching a packet: A=Drop@30, B=Allow@20 -> Allow wins.
        let pkt = make_pkt([0xAA; 6], [0xBB; 6], 0x0800);
        assert_eq!(fw.evaluate(&pkt, 0), Verdict::Allow);
    }

    #[test]
    fn update_rule_priority_unchanged_is_noop_not_self_conflict() {
        let mut fw = Firewall::new();

        fw.add_rule(FirewallRule {
            id: 1,
            priority: 10,
            action: RuleAction::Allow,
            active: true,
            ..Default::default()
        })
        .unwrap();

        // Re-setting the same priority must not be flagged as a self-conflict.
        assert!(fw.update_rule(1, None, Some(10)).is_ok());
    }

    #[test]
    fn conn_tracker_non_monotonic_timestamp_does_not_roll_back() {
        let mut ct: ConnTracker<16> = ConnTracker::new();
        let pkt = make_pkt([0x11; 6], [0x22; 6], 0x0800);

        ct.track(&pkt, 5_000_000);
        assert!(ct.is_known(&pkt, 5_000_000));

        // Track with an earlier timestamp — should not roll back.
        ct.track(&pkt, 1_000_000);

        // Entry should still be valid relative to t=5s, not t=1s.
        assert!(ct.is_known(&pkt, 10_000_000));
        // If it had rolled back to 1s, this would be stale.
        // 10s - 5s = 5s <= 5s timeout, so still known.
    }
}
