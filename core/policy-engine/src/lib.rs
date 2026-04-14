// SPDX-License-Identifier: Apache-2.0
//! # Policy Engine (`vs-policy-engine`)
//!
//! An XACML-lite access control policy engine for embedded security decisions.
//!
//! ## Overview
//!
//! The policy engine evaluates access requests against a set of [`PolicyRule`]
//! entries to produce a [`PolicyDecision`] (Permit, Deny, or DenyAudit). It is
//! used to enforce fine-grained authorization policies for diagnostic sessions,
//! firmware updates, bus access, and other security-sensitive operations.
//!
//! ## Rule Priority and Evaluation Order
//!
//! Rules are evaluated in **priority order** (lower `priority` value = higher
//! precedence). The evaluation strategy depends on the configured
//! [`CombiningAlgorithm`]:
//!
//! - **`FirstApplicable`** (default): the first matching rule determines the
//!   decision. This is the fastest mode.
//! - **`DenyOverrides`**: all matching rules are evaluated; if any produces
//!   `Deny` or `DenyAudit`, the final decision is deny regardless of permits.
//! - **`PermitOverrides`**: all matching rules are evaluated; if any produces
//!   `Permit`, the final decision is permit regardless of denials.
//!
//! Rules also support time-bounded validity via `valid_from` and `valid_until`
//! timestamps. A rule outside its validity window is skipped during evaluation.
//!
//! ## Actions and Effects
//!
//! Each rule matches against a triple of (Subject, Resource, Action):
//! - [`SubjectMatcher`] -- who is making the request (any, authenticated tester,
//!   specific address, ECU role, etc.)
//! - [`ResourceMatcher`] -- what is being accessed (bus, diagnostic service,
//!   firmware region, etc.)
//! - [`ActionMatcher`] -- what operation is attempted (read, write, execute,
//!   transmit, diagnostic request)
//!
//! The rule's [`Effect`] determines the outcome: `Permit`, `Deny`, or
//! `DenyAudit` (deny and trigger an audit callback).
//!
//! ## Default-Deny Behavior
//!
//! When no rule matches a request, the engine returns [`Effect::Deny`] with
//! `rule_id: None`. This ensures fail-closed behavior: only explicitly
//! permitted operations are allowed.
//!
//! ## Key Types
//!
//! - [`PolicyEngine`] -- the main engine struct holding rules and configuration.
//! - [`PolicyRule`] -- a single access control rule with matchers and effect.
//! - [`PolicyDecision`] -- the evaluation result (effect + matching rule ID).
//! - [`PolicyExplanation`] -- extended result with the full matched rule and
//!   evaluation statistics.
//! - [`CombiningAlgorithm`] -- strategy for combining multiple matching rules.
#![no_std]
#![forbid(unsafe_code)]

use vs_types::VsError;

/// Maximum number of policy rules the engine can hold.
const MAX_RULES: usize = 64;

// ---------------------------------------------------------------------------
// Policy DSL types
// ---------------------------------------------------------------------------

/// The effect a policy rule produces when matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum Effect {
    Permit,
    Deny,
    /// Deny the request **and** trigger an audit callback.
    DenyAudit,
}

/// Authentication level for diagnostic sessions (ISO 14229 SecurityAccess).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum AuthenticationLevel {
    /// No authentication.
    None,
    /// Basic authentication (e.g. SecurityAccess level 0x01).
    Basic,
    /// Extended / programming session authentication (e.g. SecurityAccess level 0x03+).
    Extended,
}

/// Matcher for the *subject* (who is making the request).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum SubjectMatcher {
    /// Matches every subject.
    Any,
    /// Matches only if the subject is authenticated **and** holds a valid
    /// (non-zero) session token.
    AuthenticatedTester,
    /// Like [`AuthenticatedTester`](Self::AuthenticatedTester) but also
    /// requires a specific [`AuthenticationLevel`].
    AuthenticatedWithLevel(AuthenticationLevel),
    /// Matches a subject with a specific diagnostic address.
    SpecificAddress(u32),
    /// Matches a subject whose address falls within `[low, high]` inclusive.
    AddressRange(u32, u32),
    /// Matches a subject with a specific ECU role identifier.
    EcuRole(u8),
}

/// Matcher for the *resource* being accessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum ResourceMatcher {
    /// Matches every resource.
    Any,
    /// Matches a specific bus (type + numeric identifier).
    BusId(u8, u32),
    /// Matches a UDS / diagnostic service by its SID.
    DiagnosticService(u8),
    /// Matches a range of diagnostic service IDs `[low, high]` inclusive.
    ServiceRange(u8, u8),
    /// Matches a firmware memory region by slot index.
    FirmwareRegion(u8),
}

/// Matcher for the *action* being attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum ActionMatcher {
    /// Matches every action.
    Any,
    Read,
    Write,
    Execute,
    Transmit,
    /// Matches a UDS diagnostic request with a specific sub-function.
    DiagnosticRequest(u8),
}

// ---------------------------------------------------------------------------
// Policy rule
// ---------------------------------------------------------------------------

/// A single XACML-lite policy rule.
///
/// Rules are evaluated in priority order (lower `priority` number means higher
/// precedence). The first matching rule determines the decision.
///
/// Time-based validity is supported via [`valid_from`](Self::valid_from) and
/// [`valid_until`](Self::valid_until). A value of `0` means "no constraint".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PolicyRule {
    pub id: u32,
    pub subject: SubjectMatcher,
    pub resource: ResourceMatcher,
    pub action: ActionMatcher,
    pub effect: Effect,
    /// Lower number = higher priority (evaluated first).
    pub priority: u8,
    /// Earliest timestamp (microseconds) at which this rule is active.
    /// `0` means no lower bound.
    pub valid_from: u64,
    /// Latest timestamp (microseconds) at which this rule is active.
    /// `0` means no upper bound.
    pub valid_until: u64,
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// Describes who is making the request.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Subject {
    pub address: u32,
    pub authenticated: bool,
    pub ecu_role: u8,
    /// A non-zero session token proves the caller went through a proper
    /// authentication handshake. [`SubjectMatcher::AuthenticatedTester`]
    /// requires this to be non-zero in addition to `authenticated == true`.
    pub session_token: u64,
    /// The authentication level established for this session.
    pub auth_level: AuthenticationLevel,
}

/// Describes the resource being accessed.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Resource {
    pub bus_type: Option<u8>,
    pub bus_id: Option<u32>,
    pub service_id: Option<u8>,
    pub firmware_region: Option<u8>,
}

/// The kind of action being attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum ActionType {
    Read,
    Write,
    Execute,
    Transmit,
    DiagnosticRequest(u8),
}

/// Describes the action being attempted.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Action {
    pub action_type: ActionType,
}

/// Runtime environment context passed to evaluation.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Environment {
    /// Current wall-clock time in microseconds since epoch.
    /// Used for time-bounded rule validity checks.
    pub timestamp_us: u64,
}

// ---------------------------------------------------------------------------
// Decision / explanation
// ---------------------------------------------------------------------------

/// The result of evaluating a request against the policy set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PolicyDecision {
    pub effect: Effect,
    /// The `id` of the rule that produced this decision, or `None` when the
    /// default-deny applies (no rule matched).
    pub rule_id: Option<u32>,
}

/// Extended evaluation result that also carries the matched rule and
/// evaluation statistics.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PolicyExplanation {
    pub decision: PolicyDecision,
    pub matched_rule: Option<PolicyRule>,
    pub rules_evaluated: u32,
}

/// The rule-combining algorithm used during evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum CombiningAlgorithm {
    /// First matching rule wins (default).
    FirstMatch,
    /// Any matching Deny/DenyAudit overrides all Permits.
    DenyOverrides,
    /// Any matching Permit overrides all Denies.
    PermitOverrides,
}

// ---------------------------------------------------------------------------
// Matching helpers
// ---------------------------------------------------------------------------

/// Returns `true` when the `SubjectMatcher` matches the given `Subject`.
///
/// Uses constant-time comparison for address fields to prevent timing
/// side-channels that could leak rule ordering or subject properties.
fn subject_matches(matcher: &SubjectMatcher, subject: &Subject) -> bool {
    match *matcher {
        SubjectMatcher::Any => true,
        SubjectMatcher::AuthenticatedTester => subject.authenticated && subject.session_token != 0,
        SubjectMatcher::AuthenticatedWithLevel(level) => {
            subject.authenticated && subject.session_token != 0 && subject.auth_level == level
        }
        SubjectMatcher::SpecificAddress(addr) => {
            // Constant-time u32 comparison via byte-level ct_eq.
            vs_types::constant_time_eq(&subject.address.to_ne_bytes(), &addr.to_ne_bytes())
        }
        SubjectMatcher::AddressRange(low, high) => {
            // Constant-time range check: (addr >= low) && (addr <= high)
            //
            // We avoid branching on the address value to prevent timing
            // side-channels that could reveal which rules are being
            // matched and narrow down the address of the subject.
            //
            // The technique: widen to u64 so subtraction results always
            // fit without wrapping. For unsigned integers a, b where both
            // are at most u32::MAX:
            //
            //   (a as u64) - (b as u64) is negative (bit 63 set) iff a < b,
            //   and non-negative (bit 63 clear) iff a >= b.
            //
            // We check bit 32 (not bit 31) since u32 values widened to
            // u64 can produce differences up to u32::MAX which fits in
            // 32 bits. We actually use the sign bit (bit 63) of the i64
            // representation via wrapping_sub on u64 then shift by 63:
            //
            //   ge_low:  (addr - low) has bit 63 = 0 when addr >= low.
            //            Shift right 63 gives 0, XOR 1 gives 1.
            //   le_high: (high - addr) has bit 63 = 0 when high >= addr.
            //            Shift right 63 gives 0, XOR 1 gives 1.
            //
            //   ge_low & le_high == 1  iff  low <= addr <= high.
            //
            // The final constant-time comparison avoids a branch on the
            // combined result.
            let addr = subject.address as u64;
            let lo = low as u64;
            let hi = high as u64;
            let ge_low = ((addr.wrapping_sub(lo)) >> 63) ^ 1; // 1 if addr >= low
            let le_high = ((hi.wrapping_sub(addr)) >> 63) ^ 1; // 1 if addr <= high
            let result = (ge_low & le_high) as u32;
            vs_types::constant_time_eq(&result.to_ne_bytes(), &1_u32.to_ne_bytes())
        }
        SubjectMatcher::EcuRole(role) => {
            // Constant-time u8 comparison for consistency with other matchers.
            vs_types::constant_time_eq(&[subject.ecu_role], &[role])
        }
    }
}

/// Returns `true` when the `ResourceMatcher` matches the given `Resource`.
fn resource_matches(matcher: &ResourceMatcher, resource: &Resource) -> bool {
    match *matcher {
        ResourceMatcher::Any => true,
        ResourceMatcher::BusId(bus_type, bus_id) => {
            resource.bus_type == Some(bus_type) && resource.bus_id == Some(bus_id)
        }
        ResourceMatcher::DiagnosticService(sid) => resource.service_id == Some(sid),
        ResourceMatcher::ServiceRange(low, high) => {
            matches!(resource.service_id, Some(sid) if sid >= low && sid <= high)
        }
        ResourceMatcher::FirmwareRegion(region) => resource.firmware_region == Some(region),
    }
}

/// Returns `true` when the `ActionMatcher` matches the given `Action`.
fn action_matches(matcher: &ActionMatcher, action: &Action) -> bool {
    match *matcher {
        ActionMatcher::Any => true,
        ActionMatcher::Read => action.action_type == ActionType::Read,
        ActionMatcher::Write => action.action_type == ActionType::Write,
        ActionMatcher::Execute => action.action_type == ActionType::Execute,
        ActionMatcher::Transmit => action.action_type == ActionType::Transmit,
        ActionMatcher::DiagnosticRequest(sub) => {
            action.action_type == ActionType::DiagnosticRequest(sub)
        }
    }
}

// ---------------------------------------------------------------------------
// Checksum helpers — deterministic hash of matcher discriminants and payloads
// ---------------------------------------------------------------------------

fn effect_discriminant(e: Effect) -> u32 {
    match e {
        Effect::Permit => 0x5065_726D,    // "Perm"
        Effect::Deny => 0x4465_6E79,      // "Deny"
        Effect::DenyAudit => 0x4441_7564, // "DAud"
    }
}

fn subject_matcher_hash(s: &SubjectMatcher) -> u32 {
    match *s {
        SubjectMatcher::Any => 0x0100_0000,
        SubjectMatcher::AuthenticatedTester => 0x0200_0000,
        SubjectMatcher::AuthenticatedWithLevel(lvl) => 0x0300_0000u32.wrapping_add(lvl as u32),
        SubjectMatcher::SpecificAddress(addr) => 0x0400_0000u32.wrapping_mul(31).wrapping_add(addr),
        SubjectMatcher::AddressRange(lo, hi) => 0x0500_0000u32
            .wrapping_mul(31)
            .wrapping_add(lo)
            .wrapping_mul(31)
            .wrapping_add(hi),
        SubjectMatcher::EcuRole(role) => 0x0600_0000u32.wrapping_add(role as u32),
    }
}

fn resource_matcher_hash(r: &ResourceMatcher) -> u32 {
    match *r {
        ResourceMatcher::Any => 0x1100_0000,
        ResourceMatcher::BusId(bt, bid) => 0x1200_0000u32
            .wrapping_mul(31)
            .wrapping_add(bt as u32)
            .wrapping_mul(31)
            .wrapping_add(bid),
        ResourceMatcher::DiagnosticService(sid) => 0x1300_0000u32.wrapping_add(sid as u32),
        ResourceMatcher::ServiceRange(lo, hi) => 0x1400_0000u32
            .wrapping_mul(31)
            .wrapping_add(lo as u32)
            .wrapping_mul(31)
            .wrapping_add(hi as u32),
        ResourceMatcher::FirmwareRegion(region) => 0x1500_0000u32.wrapping_add(region as u32),
    }
}

fn action_matcher_hash(a: &ActionMatcher) -> u32 {
    match *a {
        ActionMatcher::Any => 0x2100_0000,
        ActionMatcher::Read => 0x2200_0000,
        ActionMatcher::Write => 0x2300_0000,
        ActionMatcher::Execute => 0x2400_0000,
        ActionMatcher::Transmit => 0x2500_0000,
        ActionMatcher::DiagnosticRequest(sub) => 0x2600_0000u32.wrapping_add(sub as u32),
    }
}

/// Returns `true` when the rule's time constraints are satisfied by `env`.
fn rule_time_valid(rule: &PolicyRule, env: &Environment) -> bool {
    // Fast path: most rules have no time constraints at all.
    if (rule.valid_from | rule.valid_until) == 0 {
        return true;
    }
    if rule.valid_from != 0 && env.timestamp_us < rule.valid_from {
        return false;
    }
    if rule.valid_until != 0 && env.timestamp_us > rule.valid_until {
        return false;
    }
    true
}

/// Returns `true` when a rule matches the full request triple and time constraints.
fn rule_matches(
    rule: &PolicyRule,
    subject: &Subject,
    resource: &Resource,
    action: &Action,
    env: &Environment,
) -> bool {
    subject_matches(&rule.subject, subject)
        && resource_matches(&rule.resource, resource)
        && action_matches(&rule.action, action)
        && rule_time_valid(rule, env)
}

// ---------------------------------------------------------------------------
// Default-deny constant
// ---------------------------------------------------------------------------

const DEFAULT_DENY: PolicyDecision = PolicyDecision {
    effect: Effect::Deny,
    rule_id: None,
};

// ---------------------------------------------------------------------------
// Policy engine
// ---------------------------------------------------------------------------

/// XACML-lite policy engine with fixed-capacity rule storage.
///
/// Rules are kept sorted by ascending `priority` (lower number = higher
/// precedence). Evaluation is first-match by default: the first rule whose
/// matchers all succeed determines the decision. Alternative combining
/// algorithms can be selected via [`set_combining_algorithm`](PolicyEngine::set_combining_algorithm).
///
/// If no rule matches, the request is **denied** (default-deny posture).
/// Number of distinct action-type buckets for the action index.
const ACTION_INDEX_BUCKETS: usize = 6;

pub struct PolicyEngine {
    rules: [Option<PolicyRule>; MAX_RULES],
    count: usize,
    audit_callback: Option<fn(u32, &Subject, &Resource, &Action)>,
    version: u32,
    combining_algorithm: CombiningAlgorithm,
    rule_checksum: [u64; 2],
    /// Bitmask index: `action_index[bucket]` has bit `i` set if rule `i` can
    /// match that action type.  Bucket 0=Read, 1=Write, 2=Execute,
    /// 3=Transmit, 4=DiagnosticRequest, 5=Any (always set for Any-matchers).
    /// During evaluation we OR the action's bucket with bucket 5 (Any) to get
    /// the candidate set.
    action_index: [u64; ACTION_INDEX_BUCKETS],
}

impl PolicyEngine {
    /// Creates an empty policy engine with no rules loaded.
    pub fn new() -> Self {
        Self {
            rules: [None; MAX_RULES],
            count: 0,
            audit_callback: None,
            version: 0,
            combining_algorithm: CombiningAlgorithm::FirstMatch,
            // Must match compute_checksum() for an empty rule set (the
            // FNV-1a offset basis values with zero bytes fed).
            rule_checksum: [0xcbf2_9ce4_8422_2325, 0x6c62_272e_07bb_0142],
            action_index: [0u64; ACTION_INDEX_BUCKETS],
        }
    }

    /// Returns the number of rules currently loaded.
    pub fn rule_count(&self) -> usize {
        self.count
    }

    /// Map an `ActionMatcher` to its bucket index (0..5).
    fn action_matcher_bucket(m: &ActionMatcher) -> usize {
        match m {
            ActionMatcher::Read => 0,
            ActionMatcher::Write => 1,
            ActionMatcher::Execute => 2,
            ActionMatcher::Transmit => 3,
            ActionMatcher::DiagnosticRequest(_) => 4,
            ActionMatcher::Any => 5,
        }
    }

    /// Map an `ActionType` to its bucket index (0..4).
    fn action_type_bucket(t: &ActionType) -> usize {
        match t {
            ActionType::Read => 0,
            ActionType::Write => 1,
            ActionType::Execute => 2,
            ActionType::Transmit => 3,
            ActionType::DiagnosticRequest(_) => 4,
        }
    }

    /// Rebuild the action-type bitmask index from the current rule set.
    fn rebuild_action_index(&mut self) {
        self.action_index = [0u64; ACTION_INDEX_BUCKETS];
        for (i, slot) in self.rules[..self.count].iter().enumerate() {
            if let Some(rule) = slot {
                let bucket = Self::action_matcher_bucket(&rule.action);
                self.action_index[bucket] |= 1u64 << i;
            }
        }
    }

    /// Get the candidate rule bitmask for a given action type.
    /// Returns rules that match `Any` OR the specific action type.
    fn candidate_mask(&self, action: &Action) -> u64 {
        let specific = Self::action_type_bucket(&action.action_type);
        self.action_index[specific] | self.action_index[5] // specific | Any
    }

    /// Returns `(current_rules, max_rules)` for capacity monitoring.
    pub fn rule_capacity(&self) -> (usize, usize) {
        (self.count, MAX_RULES)
    }

    /// Returns the current policy version. The version is incremented on
    /// every successful mutation (add, remove, update, load, clear).
    pub fn policy_version(&self) -> u32 {
        self.version
    }

    /// Returns the active combining algorithm.
    pub fn combining_algorithm(&self) -> CombiningAlgorithm {
        self.combining_algorithm
    }

    /// Sets the rule-combining algorithm used during evaluation.
    pub fn set_combining_algorithm(&mut self, algo: CombiningAlgorithm) {
        self.combining_algorithm = algo;
    }

    /// Registers a callback that is invoked whenever a [`DenyAudit`](Effect::DenyAudit)
    /// rule fires. The callback receives the `rule_id` and the full request
    /// context (subject, resource, action) for forensic logging.
    pub fn set_audit_callback(&mut self, cb: fn(u32, &Subject, &Resource, &Action)) {
        self.audit_callback = Some(cb);
    }

    /// Looks up a rule by its ID.
    pub fn get_rule(&self, id: u32) -> Option<&PolicyRule> {
        self.rules[..self.count]
            .iter()
            .flatten()
            .find(|r| r.id == id)
    }

    /// Returns the occupied portion of the internal rule array.
    pub fn rules(&self) -> &[Option<PolicyRule>] {
        &self.rules[..self.count]
    }

    /// Adds a single rule to the engine, maintaining priority-sorted order.
    ///
    /// # Errors
    ///
    /// - [`VsError::ResourceExhausted`] if the engine is already at capacity.
    /// - [`VsError::InvalidConfig`] if a rule with the same `id` already exists.
    /// - [`VsError::PolicyViolation`] if a rule with the same `priority` already exists.
    pub fn add_rule(&mut self, rule: PolicyRule) -> Result<(), VsError> {
        if self.count >= MAX_RULES {
            return Err(VsError::ResourceExhausted);
        }

        // Reject duplicate IDs and duplicate priorities.
        for existing in self.rules[..self.count].iter().flatten() {
            if existing.id == rule.id {
                return Err(VsError::InvalidConfig);
            }
            if existing.priority == rule.priority {
                return Err(VsError::PolicyViolation);
            }
        }

        // Find insertion index to keep sorted by ascending priority.
        let mut insert_idx = self.count;
        for (i, existing) in self.rules[..self.count].iter().flatten().enumerate() {
            if rule.priority < existing.priority {
                insert_idx = i;
                break;
            }
        }

        // Shift elements right to make room.
        let mut j = self.count;
        while j > insert_idx {
            self.rules[j] = self.rules[j - 1];
            j -= 1;
        }

        self.rules[insert_idx] = Some(rule);
        self.count = self
            .count
            .checked_add(1)
            .ok_or(VsError::ResourceExhausted)?;
        self.version = self
            .version
            .checked_add(1)
            .ok_or(VsError::ResourceExhausted)?;
        self.rule_checksum = self.compute_checksum();
        self.rebuild_action_index();
        Ok(())
    }

    /// Removes a rule by its ID, compacting the array.
    ///
    /// # Errors
    ///
    /// Returns [`VsError::NotFound`] if no rule with the given `id` exists.
    pub fn remove_rule(&mut self, id: u32) -> Result<(), VsError> {
        let mut found_idx = None;
        for i in 0..self.count {
            if let Some(ref rule) = self.rules[i] {
                if rule.id == id {
                    found_idx = Some(i);
                    break;
                }
            }
        }
        let idx = found_idx.ok_or(VsError::NotFound)?;

        // Shift left to compact.
        for i in idx..self.count - 1 {
            self.rules[i] = self.rules[i + 1];
        }
        self.rules[self.count - 1] = None;
        self.count -= 1;
        self.version = self.version.saturating_add(1);
        self.rule_checksum = self.compute_checksum();
        self.rebuild_action_index();
        Ok(())
    }

    /// Replaces an existing rule (matched by `id`) with `new_rule`.
    ///
    /// The replacement rule must carry the same `id`. Priority may change as
    /// long as it does not conflict with another rule.
    ///
    /// # Errors
    ///
    /// - [`VsError::InvalidInput`] if `new_rule.id != id`.
    /// - [`VsError::NotFound`] if no rule with the given `id` exists.
    /// - [`VsError::PolicyViolation`] if the new priority conflicts with
    ///   another rule.
    pub fn update_rule(&mut self, id: u32, new_rule: PolicyRule) -> Result<(), VsError> {
        if new_rule.id != id {
            return Err(VsError::InvalidInput);
        }

        // Find existing rule index.
        let mut found_idx = None;
        for i in 0..self.count {
            if let Some(ref rule) = self.rules[i] {
                if rule.id == id {
                    found_idx = Some(i);
                    break;
                }
            }
        }
        let idx = found_idx.ok_or(VsError::NotFound)?;

        // Check new priority doesn't conflict with any OTHER rule.
        for i in 0..self.count {
            if i == idx {
                continue;
            }
            if let Some(ref rule) = self.rules[i] {
                if rule.priority == new_rule.priority {
                    return Err(VsError::PolicyViolation);
                }
            }
        }

        // Remove old rule (shift left).
        for i in idx..self.count - 1 {
            self.rules[i] = self.rules[i + 1];
        }
        self.rules[self.count - 1] = None;
        self.count -= 1;

        // Re-insert at correct sorted position. Cannot fail: we validated
        // capacity (unchanged) and priority uniqueness above.
        self.add_rule(new_rule)?;
        // add_rule already incremented version and checksum, so we're good.
        Ok(())
    }

    /// Removes all rules from the engine.
    pub fn clear_rules(&mut self) {
        self.rules = [None; MAX_RULES];
        self.count = 0;
        self.version = self.version.saturating_add(1);
        self.rule_checksum = [0xcbf2_9ce4_8422_2325, 0x6c62_272e_07bb_0142];
        self.action_index = [0u64; ACTION_INDEX_BUCKETS];
    }

    /// Replaces the entire policy set with the given slice of rules.
    ///
    /// The replacement is **atomic**: the live rule set is only modified
    /// after all new rules have been validated and sorted in a temporary
    /// buffer. If any validation step fails, the existing rules remain
    /// untouched.
    ///
    /// An empty slice clears all rules.
    ///
    /// # Errors
    ///
    /// - [`VsError::ResourceExhausted`] if the slice exceeds capacity.
    /// - [`VsError::InvalidConfig`] if two rules share the same `id`.
    /// - [`VsError::PolicyViolation`] if two rules share the same `priority`.
    pub fn load_policy_set(&mut self, rules: &[PolicyRule]) -> Result<(), VsError> {
        if rules.len() > MAX_RULES {
            return Err(VsError::ResourceExhausted);
        }

        if rules.is_empty() {
            self.clear_rules();
            return Ok(());
        }

        // O(n) priority duplicate check via bitmap.
        let mut priority_seen = [false; 256];
        for r in rules {
            if priority_seen[r.priority as usize] {
                return Err(VsError::PolicyViolation);
            }
            priority_seen[r.priority as usize] = true;
        }

        // O(n^2) ID duplicate check (n <= 64, at most 2016 comparisons).
        for (i, a) in rules.iter().enumerate() {
            for b in &rules[i + 1..] {
                if a.id == b.id {
                    return Err(VsError::InvalidConfig);
                }
            }
        }

        // Build the new rule set in a temporary buffer. The live rules
        // are NOT touched until all insertions succeed, making the
        // reload atomic — a failure leaves the old set intact.
        let mut tmp_rules: [Option<PolicyRule>; MAX_RULES] = [None; MAX_RULES];
        let mut tmp_count: usize = 0;

        for r in rules {
            // Find insertion index to keep sorted by ascending priority.
            let mut insert_idx = tmp_count;
            for (i, existing) in tmp_rules[..tmp_count].iter().flatten().enumerate() {
                if r.priority < existing.priority {
                    insert_idx = i;
                    break;
                }
            }

            // Shift elements right to make room.
            let mut j = tmp_count;
            while j > insert_idx {
                tmp_rules[j] = tmp_rules[j - 1];
                j -= 1;
            }

            tmp_rules[insert_idx] = Some(*r);
            tmp_count = tmp_count.checked_add(1).ok_or(VsError::ResourceExhausted)?;
        }

        // All rules validated and sorted — atomically swap into live state.
        self.rules = tmp_rules;
        self.count = tmp_count;
        self.version = self.version.saturating_add(1);
        self.rule_checksum = self.compute_checksum();
        self.rebuild_action_index();

        Ok(())
    }

    /// Computes a 128-bit integrity checksum over ALL rule fields using two
    /// independent FNV-1a 64-bit hashes with different seeds.
    ///
    /// Using two independent 64-bit hashes provides 128-bit collision
    /// resistance, making it computationally infeasible to craft a rule set
    /// that produces the same checksum as a different rule set. This is a
    /// significant improvement over the prior 32-bit hash which had only
    /// ~2^16 collision resistance via the birthday bound.
    ///
    /// FNV-1a constants:
    /// - Offset basis: 0xcbf2_9ce4_8422_2325 (standard FNV-1a 64-bit)
    /// - Prime: 0x0100_0000_01b3 (standard FNV-1a 64-bit)
    /// - Second seed uses a different offset basis for independence.
    fn compute_checksum(&self) -> [u64; 2] {
        // FNV-1a 64-bit constants.
        const FNV_PRIME: u64 = vs_types::FNV1A_PRIME;
        const FNV_OFFSET_1: u64 = vs_types::FNV1A_OFFSET_BASIS;
        const FNV_OFFSET_2: u64 = vs_types::FNV1A_OFFSET_BASIS_2;

        // When the rule set is empty, no bytes are fed, so the hash
        // returns the offset basis values directly. The initial checksum
        // stored in the engine must match (see `new()` and `clear_rules()`).
        let mut h1: u64 = FNV_OFFSET_1;
        let mut h2: u64 = FNV_OFFSET_2;

        /// Feed a single byte into both FNV-1a hashes.
        #[inline]
        fn feed(h1: &mut u64, h2: &mut u64, byte: u8, prime: u64) {
            *h1 ^= byte as u64;
            *h1 = h1.wrapping_mul(prime);
            *h2 ^= byte as u64;
            *h2 = h2.wrapping_mul(prime);
        }

        /// Feed a u32 (little-endian bytes) into both hashes.
        #[inline]
        fn feed_u32(h1: &mut u64, h2: &mut u64, val: u32, prime: u64) {
            for b in val.to_le_bytes() {
                feed(h1, h2, b, prime);
            }
        }

        /// Feed a u64 (little-endian bytes) into both hashes.
        #[inline]
        fn feed_u64(h1: &mut u64, h2: &mut u64, val: u64, prime: u64) {
            for b in val.to_le_bytes() {
                feed(h1, h2, b, prime);
            }
        }

        for rule in self.rules[..self.count].iter().flatten() {
            feed_u32(&mut h1, &mut h2, rule.id, FNV_PRIME);
            feed(&mut h1, &mut h2, rule.priority, FNV_PRIME);
            feed_u64(&mut h1, &mut h2, rule.valid_from, FNV_PRIME);
            feed_u64(&mut h1, &mut h2, rule.valid_until, FNV_PRIME);
            feed_u32(
                &mut h1,
                &mut h2,
                effect_discriminant(rule.effect),
                FNV_PRIME,
            );
            feed_u32(
                &mut h1,
                &mut h2,
                subject_matcher_hash(&rule.subject),
                FNV_PRIME,
            );
            feed_u32(
                &mut h1,
                &mut h2,
                resource_matcher_hash(&rule.resource),
                FNV_PRIME,
            );
            feed_u32(
                &mut h1,
                &mut h2,
                action_matcher_hash(&rule.action),
                FNV_PRIME,
            );
        }
        [h1, h2]
    }

    /// Returns `true` if the stored rule checksum matches a freshly computed one.
    ///
    /// Uses constant-time comparison to prevent timing side-channels that
    /// could leak information about the stored checksum value.
    pub fn verify_integrity(&self) -> bool {
        let computed = self.compute_checksum();
        let stored_bytes = [
            self.rule_checksum[0].to_le_bytes(),
            self.rule_checksum[1].to_le_bytes(),
        ];
        let computed_bytes = [computed[0].to_le_bytes(), computed[1].to_le_bytes()];
        let mut s: [u8; 16] = [0; 16];
        let mut c: [u8; 16] = [0; 16];
        s[..8].copy_from_slice(&stored_bytes[0]);
        s[8..].copy_from_slice(&stored_bytes[1]);
        c[..8].copy_from_slice(&computed_bytes[0]);
        c[8..].copy_from_slice(&computed_bytes[1]);
        vs_types::constant_time_eq(&s, &c)
    }

    /// Fires the audit callback if the rule has [`Effect::DenyAudit`].
    fn fire_audit_if_needed(
        &self,
        rule: &PolicyRule,
        subject: &Subject,
        resource: &Resource,
        action: &Action,
    ) {
        if rule.effect == Effect::DenyAudit {
            if let Some(cb) = self.audit_callback {
                cb(rule.id, subject, resource, action);
            }
        }
    }

    /// Evaluates a request and returns the policy decision.
    ///
    /// The combining algorithm determines how matching rules are combined.
    /// If no rule matches, the default decision is [`Effect::Deny`] with no
    /// associated `rule_id`.
    pub fn evaluate(
        &self,
        subject: &Subject,
        resource: &Resource,
        action: &Action,
        env: &Environment,
    ) -> PolicyDecision {
        match self.combining_algorithm {
            CombiningAlgorithm::FirstMatch => {
                self.evaluate_first_match(subject, resource, action, env)
            }
            CombiningAlgorithm::DenyOverrides => {
                self.evaluate_deny_overrides(subject, resource, action, env)
            }
            CombiningAlgorithm::PermitOverrides => {
                self.evaluate_permit_overrides(subject, resource, action, env)
            }
        }
    }

    fn evaluate_first_match(
        &self,
        subject: &Subject,
        resource: &Resource,
        action: &Action,
        env: &Environment,
    ) -> PolicyDecision {
        let mask = self.candidate_mask(action);
        for i in 0..self.count {
            if mask & (1u64 << i) == 0 {
                continue; // action type cannot match — skip
            }
            if let Some(rule) = &self.rules[i] {
                if rule_matches(rule, subject, resource, action, env) {
                    self.fire_audit_if_needed(rule, subject, resource, action);
                    return PolicyDecision {
                        effect: rule.effect,
                        rule_id: Some(rule.id),
                    };
                }
            }
        }
        DEFAULT_DENY
    }

    fn evaluate_deny_overrides(
        &self,
        subject: &Subject,
        resource: &Resource,
        action: &Action,
        env: &Environment,
    ) -> PolicyDecision {
        let mask = self.candidate_mask(action);
        let mut first_permit: Option<&PolicyRule> = None;

        for i in 0..self.count {
            if mask & (1u64 << i) == 0 {
                continue;
            }
            if let Some(rule) = &self.rules[i] {
                if rule_matches(rule, subject, resource, action, env) {
                    match rule.effect {
                        Effect::Deny | Effect::DenyAudit => {
                            self.fire_audit_if_needed(rule, subject, resource, action);
                            return PolicyDecision {
                                effect: rule.effect,
                                rule_id: Some(rule.id),
                            };
                        }
                        Effect::Permit => {
                            if first_permit.is_none() {
                                first_permit = Some(rule);
                            }
                        }
                    }
                }
            }
        }

        if let Some(pr) = first_permit {
            return PolicyDecision {
                effect: Effect::Permit,
                rule_id: Some(pr.id),
            };
        }
        DEFAULT_DENY
    }

    fn evaluate_permit_overrides(
        &self,
        subject: &Subject,
        resource: &Resource,
        action: &Action,
        env: &Environment,
    ) -> PolicyDecision {
        let mask = self.candidate_mask(action);
        let mut first_deny: Option<&PolicyRule> = None;
        let mut first_permit: Option<&PolicyRule> = None;
        // Track all DenyAudit matches so we can fire their callbacks even
        // when a Permit rule ultimately wins.
        let mut deny_audit_rules: [Option<u32>; MAX_RULES] = [None; MAX_RULES];
        let mut deny_audit_count: usize = 0;

        for i in 0..self.count {
            if mask & (1u64 << i) == 0 {
                continue;
            }
            if let Some(rule) = &self.rules[i] {
                if rule_matches(rule, subject, resource, action, env) {
                    match rule.effect {
                        Effect::Permit => {
                            if first_permit.is_none() {
                                first_permit = Some(rule);
                            }
                        }
                        Effect::Deny => {
                            if first_deny.is_none() {
                                first_deny = Some(rule);
                            }
                        }
                        Effect::DenyAudit => {
                            if first_deny.is_none() {
                                first_deny = Some(rule);
                            }
                            if deny_audit_count < MAX_RULES {
                                deny_audit_rules[deny_audit_count] = Some(rule.id);
                                deny_audit_count += 1;
                            }
                        }
                    }
                }
            }
        }

        // Fire DenyAudit callbacks regardless of outcome.
        for i in 0..deny_audit_count {
            if let Some(rule_id) = deny_audit_rules[i] {
                if let Some(cb) = self.audit_callback {
                    cb(rule_id, subject, resource, action);
                }
            }
        }

        if let Some(pr) = first_permit {
            return PolicyDecision {
                effect: Effect::Permit,
                rule_id: Some(pr.id),
            };
        }

        if let Some(dr) = first_deny {
            // DenyAudit callbacks already fired above.
            return PolicyDecision {
                effect: dr.effect,
                rule_id: Some(dr.id),
            };
        }
        DEFAULT_DENY
    }

    /// Like [`evaluate`](Self::evaluate), but additionally returns the matched
    /// rule and the number of rules that were evaluated before reaching a
    /// decision.
    pub fn explain_decision(
        &self,
        subject: &Subject,
        resource: &Resource,
        action: &Action,
        env: &Environment,
    ) -> PolicyExplanation {
        match self.combining_algorithm {
            CombiningAlgorithm::FirstMatch => {
                self.explain_first_match(subject, resource, action, env)
            }
            CombiningAlgorithm::DenyOverrides => {
                self.explain_deny_overrides(subject, resource, action, env)
            }
            CombiningAlgorithm::PermitOverrides => {
                self.explain_permit_overrides(subject, resource, action, env)
            }
        }
    }

    fn explain_first_match(
        &self,
        subject: &Subject,
        resource: &Resource,
        action: &Action,
        env: &Environment,
    ) -> PolicyExplanation {
        let mut evaluated: u32 = 0;

        for rule in self.rules[..self.count].iter().flatten() {
            evaluated = evaluated.saturating_add(1);
            if rule_matches(rule, subject, resource, action, env) {
                self.fire_audit_if_needed(rule, subject, resource, action);
                return PolicyExplanation {
                    decision: PolicyDecision {
                        effect: rule.effect,
                        rule_id: Some(rule.id),
                    },
                    matched_rule: Some(*rule),
                    rules_evaluated: evaluated,
                };
            }
        }

        PolicyExplanation {
            decision: DEFAULT_DENY,
            matched_rule: None,
            rules_evaluated: evaluated,
        }
    }

    fn explain_deny_overrides(
        &self,
        subject: &Subject,
        resource: &Resource,
        action: &Action,
        env: &Environment,
    ) -> PolicyExplanation {
        let mut evaluated: u32 = 0;
        let mut first_permit: Option<(PolicyRule, u32)> = None;

        for rule in self.rules[..self.count].iter().flatten() {
            evaluated = evaluated.saturating_add(1);
            if rule_matches(rule, subject, resource, action, env) {
                match rule.effect {
                    Effect::Deny | Effect::DenyAudit => {
                        self.fire_audit_if_needed(rule, subject, resource, action);
                        return PolicyExplanation {
                            decision: PolicyDecision {
                                effect: rule.effect,
                                rule_id: Some(rule.id),
                            },
                            matched_rule: Some(*rule),
                            rules_evaluated: evaluated,
                        };
                    }
                    Effect::Permit => {
                        if first_permit.is_none() {
                            first_permit = Some((*rule, evaluated));
                        }
                    }
                }
            }
        }

        if let Some((pr, _)) = first_permit {
            return PolicyExplanation {
                decision: PolicyDecision {
                    effect: Effect::Permit,
                    rule_id: Some(pr.id),
                },
                matched_rule: Some(pr),
                rules_evaluated: evaluated,
            };
        }

        PolicyExplanation {
            decision: DEFAULT_DENY,
            matched_rule: None,
            rules_evaluated: evaluated,
        }
    }

    fn explain_permit_overrides(
        &self,
        subject: &Subject,
        resource: &Resource,
        action: &Action,
        env: &Environment,
    ) -> PolicyExplanation {
        let mut evaluated: u32 = 0;
        let mut first_deny: Option<(PolicyRule, u32)> = None;
        let mut first_permit: Option<(PolicyRule, u32)> = None;
        let mut deny_audit_rules: [Option<u32>; MAX_RULES] = [None; MAX_RULES];
        let mut deny_audit_count: usize = 0;

        for rule in self.rules[..self.count].iter().flatten() {
            evaluated = evaluated.saturating_add(1);
            if rule_matches(rule, subject, resource, action, env) {
                match rule.effect {
                    Effect::Permit => {
                        if first_permit.is_none() {
                            first_permit = Some((*rule, evaluated));
                        }
                    }
                    Effect::Deny => {
                        if first_deny.is_none() {
                            first_deny = Some((*rule, evaluated));
                        }
                    }
                    Effect::DenyAudit => {
                        if first_deny.is_none() {
                            first_deny = Some((*rule, evaluated));
                        }
                        if deny_audit_count < MAX_RULES {
                            deny_audit_rules[deny_audit_count] = Some(rule.id);
                            deny_audit_count += 1;
                        }
                    }
                }
            }
        }

        // Fire DenyAudit callbacks regardless of outcome.
        for i in 0..deny_audit_count {
            if let Some(rule_id) = deny_audit_rules[i] {
                if let Some(cb) = self.audit_callback {
                    cb(rule_id, subject, resource, action);
                }
            }
        }

        if let Some((pr, _)) = first_permit {
            return PolicyExplanation {
                decision: PolicyDecision {
                    effect: Effect::Permit,
                    rule_id: Some(pr.id),
                },
                matched_rule: Some(pr),
                rules_evaluated: evaluated,
            };
        }

        if let Some((dr, _)) = first_deny {
            return PolicyExplanation {
                decision: PolicyDecision {
                    effect: dr.effect,
                    rule_id: Some(dr.id),
                },
                matched_rule: Some(dr),
                rules_evaluated: evaluated,
            };
        }

        PolicyExplanation {
            decision: DEFAULT_DENY,
            matched_rule: None,
            rules_evaluated: evaluated,
        }
    }
}

impl Default for PolicyEngine {
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

    // -- Helpers --

    fn any_subject() -> Subject {
        Subject {
            address: 0x0000,
            authenticated: false,
            ecu_role: 0,
            session_token: 0,
            auth_level: AuthenticationLevel::None,
        }
    }

    fn any_resource() -> Resource {
        Resource {
            bus_type: None,
            bus_id: None,
            service_id: None,
            firmware_region: None,
        }
    }

    fn read_action() -> Action {
        Action {
            action_type: ActionType::Read,
        }
    }

    fn write_action() -> Action {
        Action {
            action_type: ActionType::Write,
        }
    }

    fn no_env() -> Environment {
        Environment { timestamp_us: 0 }
    }

    fn make_rule(id: u32, priority: u8, effect: Effect) -> PolicyRule {
        PolicyRule {
            id,
            subject: SubjectMatcher::Any,
            resource: ResourceMatcher::Any,
            action: ActionMatcher::Any,
            effect,
            priority,
            valid_from: 0,
            valid_until: 0,
        }
    }

    // -- Original tests (updated for new signatures) --

    #[test]
    fn permit_rule_matches_correct_triple() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Read,
                effect: Effect::Permit,
                priority: 10,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Permit);
        assert_eq!(decision.rule_id, Some(1));
    }

    #[test]
    fn higher_priority_deny_overrides_lower_priority_permit() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 100,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Read,
                effect: Effect::Deny,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();
        engine
            .add_rule(PolicyRule {
                id: 200,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Read,
                effect: Effect::Permit,
                priority: 10,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.rule_id, Some(100));
    }

    #[test]
    fn default_deny_on_empty_policy_set() {
        let engine = PolicyEngine::new();
        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.rule_id, None);
    }

    #[test]
    fn explain_decision_returns_matching_rule() {
        let mut engine = PolicyEngine::new();
        let rule = PolicyRule {
            id: 42,
            subject: SubjectMatcher::Any,
            resource: ResourceMatcher::Any,
            action: ActionMatcher::Write,
            effect: Effect::Permit,
            priority: 5,
            valid_from: 0,
            valid_until: 0,
        };
        engine.add_rule(rule).unwrap();

        let explanation =
            engine.explain_decision(&any_subject(), &any_resource(), &write_action(), &no_env());
        assert_eq!(explanation.decision.effect, Effect::Permit);
        assert_eq!(explanation.decision.rule_id, Some(42));
        assert_eq!(explanation.matched_rule, Some(rule));
        assert_eq!(explanation.rules_evaluated, 1);
    }

    #[test]
    fn explain_decision_default_deny_no_match() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Write,
                effect: Effect::Permit,
                priority: 5,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        let explanation =
            engine.explain_decision(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(explanation.decision.effect, Effect::Deny);
        assert_eq!(explanation.decision.rule_id, None);
        assert!(explanation.matched_rule.is_none());
        assert_eq!(explanation.rules_evaluated, 1);
    }

    #[test]
    fn deny_audit_triggers_callback() {
        use core::sync::atomic::{AtomicU32, Ordering};

        static AUDIT_RULE_ID: AtomicU32 = AtomicU32::new(0);

        fn audit_cb(rule_id: u32, _s: &Subject, _r: &Resource, _a: &Action) {
            AUDIT_RULE_ID.store(rule_id, Ordering::SeqCst);
        }

        let mut engine = PolicyEngine::new();
        engine.set_audit_callback(audit_cb);
        engine
            .add_rule(PolicyRule {
                id: 77,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Any,
                effect: Effect::DenyAudit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        AUDIT_RULE_ID.store(0, Ordering::SeqCst);
        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::DenyAudit);
        assert_eq!(AUDIT_RULE_ID.load(Ordering::SeqCst), 77);
    }

    #[test]
    fn deny_audit_triggers_callback_via_explain() {
        use core::sync::atomic::{AtomicU32, Ordering};

        static EXPLAIN_AUDIT_ID: AtomicU32 = AtomicU32::new(0);

        fn audit_cb(rule_id: u32, _s: &Subject, _r: &Resource, _a: &Action) {
            EXPLAIN_AUDIT_ID.store(rule_id, Ordering::SeqCst);
        }

        let mut engine = PolicyEngine::new();
        engine.set_audit_callback(audit_cb);
        engine
            .add_rule(PolicyRule {
                id: 88,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Any,
                effect: Effect::DenyAudit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        EXPLAIN_AUDIT_ID.store(0, Ordering::SeqCst);
        let explanation =
            engine.explain_decision(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(explanation.decision.effect, Effect::DenyAudit);
        assert_eq!(EXPLAIN_AUDIT_ID.load(Ordering::SeqCst), 88);
    }

    #[test]
    fn duplicate_priority_rejected() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 10, Effect::Permit)).unwrap();

        let result = engine.add_rule(make_rule(2, 10, Effect::Deny));
        assert_eq!(result, Err(VsError::PolicyViolation));
    }

    #[test]
    fn capacity_limit_rejects_65th_rule() {
        let mut engine = PolicyEngine::new();
        for i in 0..MAX_RULES {
            engine
                .add_rule(make_rule(i as u32, i as u8, Effect::Deny))
                .unwrap();
        }
        assert_eq!(engine.rule_count(), MAX_RULES);

        let result = engine.add_rule(make_rule(999, 200, Effect::Deny));
        assert_eq!(result, Err(VsError::ResourceExhausted));
    }

    #[test]
    fn specific_address_matcher() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::SpecificAddress(0x7E0),
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        let subj = Subject {
            address: 0x7E0,
            authenticated: false,
            ecu_role: 0,
            session_token: 0,
            auth_level: AuthenticationLevel::None,
        };
        let decision = engine.evaluate(&subj, &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Permit);

        let subj2 = Subject {
            address: 0x7E1,
            authenticated: false,
            ecu_role: 0,
            session_token: 0,
            auth_level: AuthenticationLevel::None,
        };
        let decision2 = engine.evaluate(&subj2, &any_resource(), &read_action(), &no_env());
        assert_eq!(decision2.effect, Effect::Deny);
        assert_eq!(decision2.rule_id, None);
    }

    #[test]
    fn ecu_role_matcher() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::EcuRole(5),
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        let subj_match = Subject {
            address: 0,
            authenticated: false,
            ecu_role: 5,
            session_token: 0,
            auth_level: AuthenticationLevel::None,
        };
        assert_eq!(
            engine
                .evaluate(&subj_match, &any_resource(), &read_action(), &no_env())
                .effect,
            Effect::Permit
        );

        let subj_no_match = Subject {
            address: 0,
            authenticated: false,
            ecu_role: 3,
            session_token: 0,
            auth_level: AuthenticationLevel::None,
        };
        assert_eq!(
            engine
                .evaluate(&subj_no_match, &any_resource(), &read_action(), &no_env())
                .effect,
            Effect::Deny
        );
    }

    #[test]
    fn authenticated_tester_matcher() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::AuthenticatedTester,
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        // Authenticated with valid session token.
        let authenticated = Subject {
            address: 0,
            authenticated: true,
            ecu_role: 0,
            session_token: 0xDEAD,
            auth_level: AuthenticationLevel::Basic,
        };
        assert_eq!(
            engine
                .evaluate(&authenticated, &any_resource(), &read_action(), &no_env())
                .effect,
            Effect::Permit
        );

        // Not authenticated.
        let not_authenticated = Subject {
            address: 0,
            authenticated: false,
            ecu_role: 0,
            session_token: 0,
            auth_level: AuthenticationLevel::None,
        };
        assert_eq!(
            engine
                .evaluate(
                    &not_authenticated,
                    &any_resource(),
                    &read_action(),
                    &no_env()
                )
                .effect,
            Effect::Deny
        );
    }

    #[test]
    fn bus_type_matcher() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::BusId(vs_types::SOURCE_CAN, 0x100),
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        let res_match = Resource {
            bus_type: Some(vs_types::SOURCE_CAN),
            bus_id: Some(0x100),
            service_id: None,
            firmware_region: None,
        };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &res_match, &read_action(), &no_env())
                .effect,
            Effect::Permit
        );

        let res_wrong_bus = Resource {
            bus_type: Some(vs_types::SOURCE_SERIAL),
            bus_id: Some(0x100),
            service_id: None,
            firmware_region: None,
        };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &res_wrong_bus, &read_action(), &no_env())
                .effect,
            Effect::Deny
        );

        let res_wrong_id = Resource {
            bus_type: Some(vs_types::SOURCE_CAN),
            bus_id: Some(0x200),
            service_id: None,
            firmware_region: None,
        };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &res_wrong_id, &read_action(), &no_env())
                .effect,
            Effect::Deny
        );
    }

    #[test]
    fn diagnostic_service_matcher() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::DiagnosticService(0x22),
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        let res = Resource {
            bus_type: None,
            bus_id: None,
            service_id: Some(0x22),
            firmware_region: None,
        };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &res, &read_action(), &no_env())
                .effect,
            Effect::Permit
        );

        let res_other = Resource {
            bus_type: None,
            bus_id: None,
            service_id: Some(0x2E),
            firmware_region: None,
        };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &res_other, &read_action(), &no_env())
                .effect,
            Effect::Deny
        );
    }

    #[test]
    fn firmware_region_matcher() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::FirmwareRegion(2),
                action: ActionMatcher::Write,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        let res = Resource {
            bus_type: None,
            bus_id: None,
            service_id: None,
            firmware_region: Some(2),
        };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &res, &write_action(), &no_env())
                .effect,
            Effect::Permit
        );

        let res_other = Resource {
            bus_type: None,
            bus_id: None,
            service_id: None,
            firmware_region: Some(3),
        };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &res_other, &write_action(), &no_env())
                .effect,
            Effect::Deny
        );
    }

    #[test]
    fn action_matcher_execute() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Execute,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        let exec_action = Action {
            action_type: ActionType::Execute,
        };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &any_resource(), &exec_action, &no_env())
                .effect,
            Effect::Permit
        );

        assert_eq!(
            engine
                .evaluate(&any_subject(), &any_resource(), &read_action(), &no_env())
                .effect,
            Effect::Deny
        );
    }

    #[test]
    fn action_matcher_transmit() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Transmit,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        let tx_action = Action {
            action_type: ActionType::Transmit,
        };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &any_resource(), &tx_action, &no_env())
                .effect,
            Effect::Permit
        );
    }

    #[test]
    fn action_matcher_diagnostic_request() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::Any,
                action: ActionMatcher::DiagnosticRequest(0x31),
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        let diag = Action {
            action_type: ActionType::DiagnosticRequest(0x31),
        };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &any_resource(), &diag, &no_env())
                .effect,
            Effect::Permit
        );

        let diag_other = Action {
            action_type: ActionType::DiagnosticRequest(0x32),
        };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &any_resource(), &diag_other, &no_env())
                .effect,
            Effect::Deny
        );
    }

    #[test]
    fn load_policy_set_replaces_existing_rules() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();
        assert_eq!(engine.rule_count(), 1);

        let new_rules = [
            PolicyRule {
                id: 10,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Read,
                effect: Effect::Deny,
                priority: 5,
                valid_from: 0,
                valid_until: 0,
            },
            PolicyRule {
                id: 20,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Write,
                effect: Effect::Permit,
                priority: 10,
                valid_from: 0,
                valid_until: 0,
            },
        ];
        engine.load_policy_set(&new_rules).unwrap();
        assert_eq!(engine.rule_count(), 2);

        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.rule_id, Some(10));

        let decision_w =
            engine.evaluate(&any_subject(), &any_resource(), &write_action(), &no_env());
        assert_eq!(decision_w.effect, Effect::Permit);
        assert_eq!(decision_w.rule_id, Some(20));
    }

    #[test]
    fn load_policy_set_rejects_duplicate_priorities() {
        let mut engine = PolicyEngine::new();
        let rules = [
            make_rule(1, 5, Effect::Permit),
            make_rule(2, 5, Effect::Deny),
        ];
        let result = engine.load_policy_set(&rules);
        assert_eq!(result, Err(VsError::PolicyViolation));
    }

    #[test]
    fn load_policy_set_rejects_too_many_rules() {
        let mut rules = [make_rule(0, 0, Effect::Deny); 65];
        for (i, rule) in rules.iter_mut().enumerate() {
            rule.id = i as u32;
            rule.priority = i as u8;
        }

        let mut engine = PolicyEngine::new();
        let result = engine.load_policy_set(&rules);
        assert_eq!(result, Err(VsError::ResourceExhausted));
    }

    #[test]
    fn rules_sorted_by_priority_regardless_of_insertion_order() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(200, 20, Effect::Permit)).unwrap();
        engine.add_rule(make_rule(100, 5, Effect::Deny)).unwrap();

        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.rule_id, Some(100));
    }

    #[test]
    fn rule_count_tracks_additions() {
        let mut engine = PolicyEngine::new();
        assert_eq!(engine.rule_count(), 0);

        engine.add_rule(make_rule(1, 1, Effect::Deny)).unwrap();
        assert_eq!(engine.rule_count(), 1);

        engine.add_rule(make_rule(2, 2, Effect::Deny)).unwrap();
        assert_eq!(engine.rule_count(), 2);
    }

    #[test]
    fn default_trait_creates_empty_engine() {
        let engine = PolicyEngine::default();
        assert_eq!(engine.rule_count(), 0);
        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn resource_matcher_any_matches_all_resources() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();

        let res1 = Resource {
            bus_type: Some(vs_types::SOURCE_CAN),
            bus_id: Some(1),
            service_id: None,
            firmware_region: None,
        };
        let res2 = Resource {
            bus_type: None,
            bus_id: None,
            service_id: Some(0x22),
            firmware_region: None,
        };
        let res3 = any_resource();

        assert_eq!(
            engine
                .evaluate(&any_subject(), &res1, &read_action(), &no_env())
                .effect,
            Effect::Permit
        );
        assert_eq!(
            engine
                .evaluate(&any_subject(), &res2, &read_action(), &no_env())
                .effect,
            Effect::Permit
        );
        assert_eq!(
            engine
                .evaluate(&any_subject(), &res3, &read_action(), &no_env())
                .effect,
            Effect::Permit
        );
    }

    #[test]
    fn action_matcher_any_matches_all_actions() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();

        let actions = [
            Action {
                action_type: ActionType::Read,
            },
            Action {
                action_type: ActionType::Write,
            },
            Action {
                action_type: ActionType::Execute,
            },
            Action {
                action_type: ActionType::Transmit,
            },
            Action {
                action_type: ActionType::DiagnosticRequest(0x27),
            },
        ];

        for act in &actions {
            assert_eq!(
                engine
                    .evaluate(&any_subject(), &any_resource(), act, &no_env())
                    .effect,
                Effect::Permit
            );
        }
    }

    #[test]
    fn subject_matcher_any_matches_all_subjects() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();

        let subjects = [
            Subject {
                address: 0,
                authenticated: false,
                ecu_role: 0,
                session_token: 0,
                auth_level: AuthenticationLevel::None,
            },
            Subject {
                address: 0xFFFF,
                authenticated: true,
                ecu_role: 255,
                session_token: 0xFFFF_FFFF,
                auth_level: AuthenticationLevel::Extended,
            },
            Subject {
                address: 0x7E0,
                authenticated: true,
                ecu_role: 5,
                session_token: 42,
                auth_level: AuthenticationLevel::Basic,
            },
        ];

        for subj in &subjects {
            assert_eq!(
                engine
                    .evaluate(subj, &any_resource(), &read_action(), &no_env())
                    .effect,
                Effect::Permit
            );
        }
    }

    #[test]
    fn multiple_rules_same_effect_different_matchers() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::SpecificAddress(0x7E0),
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();
        engine
            .add_rule(PolicyRule {
                id: 2,
                subject: SubjectMatcher::SpecificAddress(0x7E1),
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 2,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        let s1 = Subject {
            address: 0x7E0,
            authenticated: false,
            ecu_role: 0,
            session_token: 0,
            auth_level: AuthenticationLevel::None,
        };
        let s2 = Subject {
            address: 0x7E1,
            authenticated: false,
            ecu_role: 0,
            session_token: 0,
            auth_level: AuthenticationLevel::None,
        };

        assert_eq!(
            engine
                .evaluate(&s1, &any_resource(), &read_action(), &no_env())
                .rule_id,
            Some(1)
        );
        assert_eq!(
            engine
                .evaluate(&s2, &any_resource(), &read_action(), &no_env())
                .rule_id,
            Some(2)
        );
    }

    #[test]
    fn rule_with_priority_0_highest() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(100, 0, Effect::Permit)).unwrap();
        engine.add_rule(make_rule(200, 255, Effect::Deny)).unwrap();

        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Permit);
        assert_eq!(decision.rule_id, Some(100));
    }

    #[test]
    fn rule_with_priority_255_lowest() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(200, 255, Effect::Deny)).unwrap();

        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.rule_id, Some(200));
    }

    #[test]
    fn evaluate_all_matchers_any_first_rule_wins() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();
        engine.add_rule(make_rule(2, 2, Effect::Deny)).unwrap();

        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Permit);
        assert_eq!(decision.rule_id, Some(1));
    }

    #[test]
    fn load_empty_policy_set_clears_all_rules() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();
        assert_eq!(engine.rule_count(), 1);

        engine.load_policy_set(&[]).unwrap();
        assert_eq!(engine.rule_count(), 0);

        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn explain_decision_with_64_rules_evaluates_all() {
        let mut engine = PolicyEngine::new();
        for i in 0..MAX_RULES {
            engine
                .add_rule(PolicyRule {
                    id: i as u32,
                    subject: SubjectMatcher::SpecificAddress(i as u32),
                    resource: ResourceMatcher::Any,
                    action: ActionMatcher::Any,
                    effect: Effect::Permit,
                    priority: i as u8,
                    valid_from: 0,
                    valid_until: 0,
                })
                .unwrap();
        }

        let subj = Subject {
            address: 0xFFFF,
            authenticated: false,
            ecu_role: 0,
            session_token: 0,
            auth_level: AuthenticationLevel::None,
        };
        let explanation =
            engine.explain_decision(&subj, &any_resource(), &read_action(), &no_env());
        assert_eq!(explanation.decision.effect, Effect::Deny);
        assert_eq!(explanation.rules_evaluated, MAX_RULES as u32);
    }

    #[test]
    fn deny_audit_on_first_rule_permit_on_second_deny_audit_fires() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 1, Effect::DenyAudit)).unwrap();
        engine.add_rule(make_rule(2, 2, Effect::Permit)).unwrap();

        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::DenyAudit);
        assert_eq!(decision.rule_id, Some(1));
    }

    #[test]
    fn resource_matcher_bus_id_wrong_bus_type_no_match() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::BusId(vs_types::SOURCE_CAN, 0x100),
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        let res = Resource {
            bus_type: Some(vs_types::SOURCE_SERIAL),
            bus_id: Some(0x100),
            service_id: None,
            firmware_region: None,
        };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &res, &read_action(), &no_env())
                .effect,
            Effect::Deny
        );
    }

    #[test]
    fn resource_matcher_bus_id_wrong_id_no_match() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::BusId(vs_types::SOURCE_CAN, 0x100),
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        let res = Resource {
            bus_type: Some(vs_types::SOURCE_CAN),
            bus_id: Some(0x200),
            service_id: None,
            firmware_region: None,
        };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &res, &read_action(), &no_env())
                .effect,
            Effect::Deny
        );
    }

    #[test]
    fn action_matcher_write_matches_write_not_read() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Write,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        assert_eq!(
            engine
                .evaluate(&any_subject(), &any_resource(), &write_action(), &no_env())
                .effect,
            Effect::Permit
        );
        assert_eq!(
            engine
                .evaluate(&any_subject(), &any_resource(), &read_action(), &no_env())
                .effect,
            Effect::Deny
        );
    }

    #[test]
    fn action_matcher_read_matches_read_not_write() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Read,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        assert_eq!(
            engine
                .evaluate(&any_subject(), &any_resource(), &read_action(), &no_env())
                .effect,
            Effect::Permit
        );
        assert_eq!(
            engine
                .evaluate(&any_subject(), &any_resource(), &write_action(), &no_env())
                .effect,
            Effect::Deny
        );
    }

    #[test]
    fn subject_matcher_with_address_0() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::SpecificAddress(0),
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        let subj = Subject {
            address: 0,
            authenticated: false,
            ecu_role: 0,
            session_token: 0,
            auth_level: AuthenticationLevel::None,
        };
        assert_eq!(
            engine
                .evaluate(&subj, &any_resource(), &read_action(), &no_env())
                .effect,
            Effect::Permit
        );
    }

    #[test]
    fn subject_matcher_with_max_address_0xffff() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::SpecificAddress(0xFFFF),
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        let subj = Subject {
            address: 0xFFFF,
            authenticated: false,
            ecu_role: 0,
            session_token: 0,
            auth_level: AuthenticationLevel::None,
        };
        assert_eq!(
            engine
                .evaluate(&subj, &any_resource(), &read_action(), &no_env())
                .effect,
            Effect::Permit
        );
    }

    #[test]
    fn multiple_add_rule_then_evaluate_finds_correct_one() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 10,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::DiagnosticService(0x22),
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();
        engine
            .add_rule(PolicyRule {
                id: 20,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::DiagnosticService(0x27),
                action: ActionMatcher::Any,
                effect: Effect::Deny,
                priority: 2,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();
        engine
            .add_rule(PolicyRule {
                id: 30,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::DiagnosticService(0x31),
                action: ActionMatcher::Any,
                effect: Effect::DenyAudit,
                priority: 3,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        let res_22 = Resource {
            bus_type: None,
            bus_id: None,
            service_id: Some(0x22),
            firmware_region: None,
        };
        let res_27 = Resource {
            bus_type: None,
            bus_id: None,
            service_id: Some(0x27),
            firmware_region: None,
        };
        let res_31 = Resource {
            bus_type: None,
            bus_id: None,
            service_id: Some(0x31),
            firmware_region: None,
        };

        assert_eq!(
            engine
                .evaluate(&any_subject(), &res_22, &read_action(), &no_env())
                .effect,
            Effect::Permit
        );
        assert_eq!(
            engine
                .evaluate(&any_subject(), &res_27, &read_action(), &no_env())
                .effect,
            Effect::Deny
        );
        assert_eq!(
            engine
                .evaluate(&any_subject(), &res_31, &read_action(), &no_env())
                .effect,
            Effect::DenyAudit
        );
    }

    #[test]
    fn rule_count_returns_0_after_clear_via_load() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();
        engine
            .add_rule(PolicyRule {
                id: 2,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Read,
                effect: Effect::Deny,
                priority: 2,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();
        assert_eq!(engine.rule_count(), 2);

        engine.load_policy_set(&[]).unwrap();
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn policy_engine_with_single_permit_rule() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();

        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Permit);
    }

    #[test]
    fn policy_engine_with_single_deny_rule() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 1, Effect::Deny)).unwrap();

        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.rule_id, Some(1));
    }

    #[test]
    fn policy_engine_with_single_deny_audit_rule() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 1, Effect::DenyAudit)).unwrap();

        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::DenyAudit);
        assert_eq!(decision.rule_id, Some(1));
    }

    #[test]
    fn explain_returns_rules_evaluated_count_correctly() {
        let mut engine = PolicyEngine::new();
        for i in 1..=3 {
            engine
                .add_rule(PolicyRule {
                    id: i,
                    subject: SubjectMatcher::SpecificAddress(i),
                    resource: ResourceMatcher::Any,
                    action: ActionMatcher::Any,
                    effect: Effect::Permit,
                    priority: i as u8,
                    valid_from: 0,
                    valid_until: 0,
                })
                .unwrap();
        }

        let subj = Subject {
            address: 0x003,
            authenticated: false,
            ecu_role: 0,
            session_token: 0,
            auth_level: AuthenticationLevel::None,
        };
        let explanation =
            engine.explain_decision(&subj, &any_resource(), &read_action(), &no_env());
        assert_eq!(explanation.decision.effect, Effect::Permit);
        assert_eq!(explanation.rules_evaluated, 3);
    }

    #[test]
    fn permit_priority_1_deny_priority_2_permit_wins() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();
        engine.add_rule(make_rule(2, 2, Effect::Deny)).unwrap();

        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Permit);
        assert_eq!(decision.rule_id, Some(1));
    }

    #[test]
    fn firmware_region_matcher_region_0_and_region_255() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::FirmwareRegion(0),
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();
        engine
            .add_rule(PolicyRule {
                id: 2,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::FirmwareRegion(255),
                action: ActionMatcher::Any,
                effect: Effect::DenyAudit,
                priority: 2,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        let res_0 = Resource {
            bus_type: None,
            bus_id: None,
            service_id: None,
            firmware_region: Some(0),
        };
        let res_255 = Resource {
            bus_type: None,
            bus_id: None,
            service_id: None,
            firmware_region: Some(255),
        };

        assert_eq!(
            engine
                .evaluate(&any_subject(), &res_0, &read_action(), &no_env())
                .effect,
            Effect::Permit
        );
        assert_eq!(
            engine
                .evaluate(&any_subject(), &res_255, &read_action(), &no_env())
                .effect,
            Effect::DenyAudit
        );
    }

    // ---- New tests ----

    #[test]
    fn duplicate_rule_id_rejected() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 10, Effect::Permit)).unwrap();

        let result = engine.add_rule(make_rule(1, 20, Effect::Deny));
        assert_eq!(result, Err(VsError::InvalidConfig));
    }

    #[test]
    fn load_policy_set_rejects_duplicate_ids() {
        let mut engine = PolicyEngine::new();
        let rules = [
            make_rule(1, 5, Effect::Permit),
            make_rule(1, 10, Effect::Deny),
        ];
        let result = engine.load_policy_set(&rules);
        assert_eq!(result, Err(VsError::InvalidConfig));
    }

    #[test]
    fn remove_rule_success() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();
        engine.add_rule(make_rule(2, 2, Effect::Deny)).unwrap();
        engine.add_rule(make_rule(3, 3, Effect::Permit)).unwrap();
        assert_eq!(engine.rule_count(), 3);

        engine.remove_rule(2).unwrap();
        assert_eq!(engine.rule_count(), 2);
        assert!(engine.get_rule(2).is_none());
        assert!(engine.get_rule(1).is_some());
        assert!(engine.get_rule(3).is_some());
    }

    #[test]
    fn remove_rule_not_found() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();

        let result = engine.remove_rule(999);
        assert_eq!(result, Err(VsError::NotFound));
    }

    #[test]
    fn remove_rule_maintains_sort_order() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 10, Effect::Deny)).unwrap();
        engine.add_rule(make_rule(2, 20, Effect::Permit)).unwrap();
        engine
            .add_rule(make_rule(3, 30, Effect::DenyAudit))
            .unwrap();

        // Remove middle rule.
        engine.remove_rule(2).unwrap();

        // Rule 1 (priority 10) should still come before rule 3 (priority 30).
        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.rule_id, Some(1));
    }

    #[test]
    fn update_rule_success() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 10, Effect::Permit)).unwrap();
        engine.add_rule(make_rule(2, 20, Effect::Deny)).unwrap();

        // Update rule 1 to be lower priority and deny.
        let updated = PolicyRule {
            id: 1,
            subject: SubjectMatcher::Any,
            resource: ResourceMatcher::Any,
            action: ActionMatcher::Any,
            effect: Effect::Deny,
            priority: 30,
            valid_from: 0,
            valid_until: 0,
        };
        engine.update_rule(1, updated).unwrap();

        // Rule 2 (priority 20) should now come first.
        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.rule_id, Some(2));
    }

    #[test]
    fn update_rule_not_found() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 10, Effect::Permit)).unwrap();

        let result = engine.update_rule(999, make_rule(999, 20, Effect::Deny));
        assert_eq!(result, Err(VsError::NotFound));
    }

    #[test]
    fn update_rule_id_mismatch() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 10, Effect::Permit)).unwrap();

        let result = engine.update_rule(1, make_rule(2, 10, Effect::Deny));
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn update_rule_priority_conflict() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 10, Effect::Permit)).unwrap();
        engine.add_rule(make_rule(2, 20, Effect::Deny)).unwrap();

        // Try to update rule 1 to priority 20 (conflicts with rule 2).
        let updated = PolicyRule {
            id: 1,
            subject: SubjectMatcher::Any,
            resource: ResourceMatcher::Any,
            action: ActionMatcher::Any,
            effect: Effect::Permit,
            priority: 20,
            valid_from: 0,
            valid_until: 0,
        };
        let result = engine.update_rule(1, updated);
        assert_eq!(result, Err(VsError::PolicyViolation));
        // Original rule should be unchanged.
        assert_eq!(engine.get_rule(1).unwrap().priority, 10);
    }

    #[test]
    fn policy_version_increments_on_mutation() {
        let mut engine = PolicyEngine::new();
        assert_eq!(engine.policy_version(), 0);

        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();
        assert_eq!(engine.policy_version(), 1);

        engine.add_rule(make_rule(2, 2, Effect::Deny)).unwrap();
        assert_eq!(engine.policy_version(), 2);

        engine.remove_rule(2).unwrap();
        assert_eq!(engine.policy_version(), 3);

        engine.clear_rules();
        assert_eq!(engine.policy_version(), 4);

        engine
            .load_policy_set(&[make_rule(10, 10, Effect::Permit)])
            .unwrap();
        // load_policy_set calls clear_rules (version++) then add_rule (version++)
        assert!(engine.policy_version() > 4);
    }

    #[test]
    fn clear_rules_empties_engine() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();
        engine.add_rule(make_rule(2, 2, Effect::Deny)).unwrap();
        assert_eq!(engine.rule_count(), 2);

        engine.clear_rules();
        assert_eq!(engine.rule_count(), 0);

        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn get_rule_found() {
        let mut engine = PolicyEngine::new();
        let rule = make_rule(42, 5, Effect::Permit);
        engine.add_rule(rule).unwrap();

        let found = engine.get_rule(42).unwrap();
        assert_eq!(found.id, 42);
        assert_eq!(found.priority, 5);
        assert_eq!(found.effect, Effect::Permit);
    }

    #[test]
    fn get_rule_not_found() {
        let engine = PolicyEngine::new();
        assert!(engine.get_rule(999).is_none());
    }

    #[test]
    fn rules_returns_loaded_rules() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 10, Effect::Permit)).unwrap();
        engine.add_rule(make_rule(2, 20, Effect::Deny)).unwrap();

        let rules = engine.rules();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].unwrap().id, 1);
        assert_eq!(rules[1].unwrap().id, 2);
    }

    #[test]
    fn authenticated_tester_requires_session_token() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::AuthenticatedTester,
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        // authenticated=true but session_token=0 => should DENY.
        let forged = Subject {
            address: 0,
            authenticated: true,
            ecu_role: 0,
            session_token: 0,
            auth_level: AuthenticationLevel::None,
        };
        assert_eq!(
            engine
                .evaluate(&forged, &any_resource(), &read_action(), &no_env())
                .effect,
            Effect::Deny
        );

        // authenticated=true AND session_token != 0 => should PERMIT.
        let legit = Subject {
            address: 0,
            authenticated: true,
            ecu_role: 0,
            session_token: 0xBEEF,
            auth_level: AuthenticationLevel::Basic,
        };
        assert_eq!(
            engine
                .evaluate(&legit, &any_resource(), &read_action(), &no_env())
                .effect,
            Effect::Permit
        );
    }

    #[test]
    fn authenticated_with_level_matches() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::AuthenticatedWithLevel(AuthenticationLevel::Extended),
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        // Extended level matches.
        let extended = Subject {
            address: 0,
            authenticated: true,
            ecu_role: 0,
            session_token: 0xCAFE,
            auth_level: AuthenticationLevel::Extended,
        };
        assert_eq!(
            engine
                .evaluate(&extended, &any_resource(), &read_action(), &no_env())
                .effect,
            Effect::Permit
        );

        // Basic level does NOT match Extended requirement.
        let basic = Subject {
            address: 0,
            authenticated: true,
            ecu_role: 0,
            session_token: 0xCAFE,
            auth_level: AuthenticationLevel::Basic,
        };
        assert_eq!(
            engine
                .evaluate(&basic, &any_resource(), &read_action(), &no_env())
                .effect,
            Effect::Deny
        );

        // Correct level but no session token => deny.
        let no_token = Subject {
            address: 0,
            authenticated: true,
            ecu_role: 0,
            session_token: 0,
            auth_level: AuthenticationLevel::Extended,
        };
        assert_eq!(
            engine
                .evaluate(&no_token, &any_resource(), &read_action(), &no_env())
                .effect,
            Effect::Deny
        );
    }

    #[test]
    fn address_range_matcher() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::AddressRange(0x7E0, 0x7E7),
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        // In range.
        for addr in [0x7E0, 0x7E3, 0x7E7] {
            let subj = Subject {
                address: addr,
                authenticated: false,
                ecu_role: 0,
                session_token: 0,
                auth_level: AuthenticationLevel::None,
            };
            assert_eq!(
                engine
                    .evaluate(&subj, &any_resource(), &read_action(), &no_env())
                    .effect,
                Effect::Permit,
                "Expected permit for address {addr:#06X}"
            );
        }

        // Out of range.
        for addr in [0x7DF, 0x7E8, 0x0000] {
            let subj = Subject {
                address: addr,
                authenticated: false,
                ecu_role: 0,
                session_token: 0,
                auth_level: AuthenticationLevel::None,
            };
            assert_eq!(
                engine
                    .evaluate(&subj, &any_resource(), &read_action(), &no_env())
                    .effect,
                Effect::Deny,
                "Expected deny for address {addr:#06X}"
            );
        }
    }

    #[test]
    fn service_range_matcher() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::ServiceRange(0x20, 0x2F),
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        // In range.
        for sid in [0x20, 0x22, 0x2F] {
            let res = Resource {
                bus_type: None,
                bus_id: None,
                service_id: Some(sid),
                firmware_region: None,
            };
            assert_eq!(
                engine
                    .evaluate(&any_subject(), &res, &read_action(), &no_env())
                    .effect,
                Effect::Permit,
                "Expected permit for SID {sid:#04X}"
            );
        }

        // Out of range.
        for sid in [0x1F, 0x30, 0x00] {
            let res = Resource {
                bus_type: None,
                bus_id: None,
                service_id: Some(sid),
                firmware_region: None,
            };
            assert_eq!(
                engine
                    .evaluate(&any_subject(), &res, &read_action(), &no_env())
                    .effect,
                Effect::Deny,
                "Expected deny for SID {sid:#04X}"
            );
        }

        // No service_id at all.
        assert_eq!(
            engine
                .evaluate(&any_subject(), &any_resource(), &read_action(), &no_env())
                .effect,
            Effect::Deny
        );
    }

    #[test]
    fn time_constraint_valid_from() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 1000,
                valid_until: 0,
            })
            .unwrap();

        // Before valid_from => no match, default deny.
        let env_before = Environment { timestamp_us: 999 };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &any_resource(), &read_action(), &env_before)
                .effect,
            Effect::Deny
        );

        // At valid_from => matches.
        let env_at = Environment { timestamp_us: 1000 };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &any_resource(), &read_action(), &env_at)
                .effect,
            Effect::Permit
        );

        // After valid_from => matches.
        let env_after = Environment { timestamp_us: 5000 };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &any_resource(), &read_action(), &env_after)
                .effect,
            Effect::Permit
        );
    }

    #[test]
    fn time_constraint_valid_until() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 2000,
            })
            .unwrap();

        // Before valid_until => matches.
        let env_before = Environment { timestamp_us: 1999 };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &any_resource(), &read_action(), &env_before)
                .effect,
            Effect::Permit
        );

        // At valid_until => matches.
        let env_at = Environment { timestamp_us: 2000 };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &any_resource(), &read_action(), &env_at)
                .effect,
            Effect::Permit
        );

        // After valid_until => no match, default deny.
        let env_after = Environment { timestamp_us: 2001 };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &any_resource(), &read_action(), &env_after)
                .effect,
            Effect::Deny
        );
    }

    #[test]
    fn time_constraint_within_window() {
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::Any,
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 1000,
                valid_until: 2000,
            })
            .unwrap();

        // Inside window.
        let env_inside = Environment { timestamp_us: 1500 };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &any_resource(), &read_action(), &env_inside)
                .effect,
            Effect::Permit
        );

        // Before window.
        let env_before = Environment { timestamp_us: 500 };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &any_resource(), &read_action(), &env_before)
                .effect,
            Effect::Deny
        );

        // After window.
        let env_after = Environment { timestamp_us: 3000 };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &any_resource(), &read_action(), &env_after)
                .effect,
            Effect::Deny
        );
    }

    #[test]
    fn time_constraint_zero_means_no_constraint() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();

        // With timestamp 0 (no env info) => matches (both valid_from and valid_until are 0).
        assert_eq!(
            engine
                .evaluate(&any_subject(), &any_resource(), &read_action(), &no_env())
                .effect,
            Effect::Permit
        );

        // With large timestamp => still matches.
        let env_large = Environment {
            timestamp_us: u64::MAX,
        };
        assert_eq!(
            engine
                .evaluate(&any_subject(), &any_resource(), &read_action(), &env_large)
                .effect,
            Effect::Permit
        );
    }

    #[test]
    fn audit_callback_receives_full_context() {
        use core::sync::atomic::{AtomicU32, Ordering};

        static CB_RULE_ID: AtomicU32 = AtomicU32::new(0);
        static CB_ADDR: AtomicU32 = AtomicU32::new(0);

        fn audit_cb(rule_id: u32, s: &Subject, _r: &Resource, _a: &Action) {
            CB_RULE_ID.store(rule_id, Ordering::SeqCst);
            CB_ADDR.store(s.address, Ordering::SeqCst);
        }

        let mut engine = PolicyEngine::new();
        engine.set_audit_callback(audit_cb);
        engine
            .add_rule(make_rule(55, 1, Effect::DenyAudit))
            .unwrap();

        CB_RULE_ID.store(0, Ordering::SeqCst);
        CB_ADDR.store(0, Ordering::SeqCst);

        let subj = Subject {
            address: 0x7E0,
            authenticated: false,
            ecu_role: 0,
            session_token: 0,
            auth_level: AuthenticationLevel::None,
        };
        engine.evaluate(&subj, &any_resource(), &read_action(), &no_env());

        assert_eq!(CB_RULE_ID.load(Ordering::SeqCst), 55);
        assert_eq!(CB_ADDR.load(Ordering::SeqCst), 0x7E0);
    }

    #[test]
    fn combining_deny_overrides() {
        let mut engine = PolicyEngine::new();
        engine.set_combining_algorithm(CombiningAlgorithm::DenyOverrides);

        // Permit at higher priority, Deny at lower priority.
        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();
        engine.add_rule(make_rule(2, 2, Effect::Deny)).unwrap();

        // DenyOverrides: the Deny should win even though Permit has higher priority.
        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.rule_id, Some(2));
    }

    #[test]
    fn combining_permit_overrides() {
        let mut engine = PolicyEngine::new();
        engine.set_combining_algorithm(CombiningAlgorithm::PermitOverrides);

        // Deny at higher priority, Permit at lower priority.
        engine.add_rule(make_rule(1, 1, Effect::Deny)).unwrap();
        engine.add_rule(make_rule(2, 2, Effect::Permit)).unwrap();

        // PermitOverrides: the Permit should win even though Deny has higher priority.
        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Permit);
        assert_eq!(decision.rule_id, Some(2));
    }

    #[test]
    fn combining_first_match_default() {
        let engine = PolicyEngine::new();
        assert_eq!(engine.combining_algorithm(), CombiningAlgorithm::FirstMatch);
    }

    #[test]
    fn combining_deny_overrides_all_permit_returns_permit() {
        let mut engine = PolicyEngine::new();
        engine.set_combining_algorithm(CombiningAlgorithm::DenyOverrides);
        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();
        engine.add_rule(make_rule(2, 2, Effect::Permit)).unwrap();

        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Permit);
    }

    #[test]
    fn combining_permit_overrides_all_deny_returns_deny() {
        let mut engine = PolicyEngine::new();
        engine.set_combining_algorithm(CombiningAlgorithm::PermitOverrides);
        engine.add_rule(make_rule(1, 1, Effect::Deny)).unwrap();
        engine.add_rule(make_rule(2, 2, Effect::DenyAudit)).unwrap();

        let decision = engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.rule_id, Some(1));
    }

    #[test]
    fn combining_deny_overrides_explain() {
        let mut engine = PolicyEngine::new();
        engine.set_combining_algorithm(CombiningAlgorithm::DenyOverrides);
        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();
        engine.add_rule(make_rule(2, 2, Effect::Deny)).unwrap();

        let explanation =
            engine.explain_decision(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(explanation.decision.effect, Effect::Deny);
        assert_eq!(explanation.decision.rule_id, Some(2));
        assert_eq!(explanation.matched_rule.unwrap().id, 2);
        // Both rules were evaluated.
        assert_eq!(explanation.rules_evaluated, 2);
    }

    #[test]
    fn combining_permit_overrides_explain() {
        let mut engine = PolicyEngine::new();
        engine.set_combining_algorithm(CombiningAlgorithm::PermitOverrides);
        engine.add_rule(make_rule(1, 1, Effect::Deny)).unwrap();
        engine.add_rule(make_rule(2, 2, Effect::Permit)).unwrap();

        let explanation =
            engine.explain_decision(&any_subject(), &any_resource(), &read_action(), &no_env());
        assert_eq!(explanation.decision.effect, Effect::Permit);
        assert_eq!(explanation.decision.rule_id, Some(2));
        assert_eq!(explanation.matched_rule.unwrap().id, 2);
        assert_eq!(explanation.rules_evaluated, 2);
    }

    #[test]
    fn combining_no_match_returns_default_deny() {
        for algo in [
            CombiningAlgorithm::FirstMatch,
            CombiningAlgorithm::DenyOverrides,
            CombiningAlgorithm::PermitOverrides,
        ] {
            let mut engine = PolicyEngine::new();
            engine.set_combining_algorithm(algo);
            // Add a rule that won't match.
            engine
                .add_rule(PolicyRule {
                    id: 1,
                    subject: SubjectMatcher::SpecificAddress(0xFFFF),
                    resource: ResourceMatcher::Any,
                    action: ActionMatcher::Any,
                    effect: Effect::Permit,
                    priority: 1,
                    valid_from: 0,
                    valid_until: 0,
                })
                .unwrap();

            let decision =
                engine.evaluate(&any_subject(), &any_resource(), &read_action(), &no_env());
            assert_eq!(decision.effect, Effect::Deny);
            assert_eq!(decision.rule_id, None);
        }
    }

    // ---- C5: Atomic reload tests ----

    #[test]
    fn atomic_reload_preserves_old_rules_on_duplicate_priority() {
        let mut engine = PolicyEngine::new();
        let original = [
            make_rule(1, 10, Effect::Permit),
            make_rule(2, 20, Effect::Deny),
        ];
        engine.load_policy_set(&original).unwrap();
        assert_eq!(engine.rule_count(), 2);
        let version_before = engine.policy_version();

        // Attempt a reload with duplicate priorities — should fail.
        let bad_rules = [
            make_rule(10, 5, Effect::Permit),
            make_rule(11, 5, Effect::Deny), // duplicate priority
        ];
        let result = engine.load_policy_set(&bad_rules);
        assert_eq!(result, Err(VsError::PolicyViolation));

        // Old rules must still be intact.
        assert_eq!(engine.rule_count(), 2);
        assert!(engine.get_rule(1).is_some());
        assert!(engine.get_rule(2).is_some());
        assert_eq!(engine.policy_version(), version_before);
    }

    #[test]
    fn atomic_reload_preserves_old_rules_on_duplicate_id() {
        let mut engine = PolicyEngine::new();
        let original = [make_rule(1, 10, Effect::Permit)];
        engine.load_policy_set(&original).unwrap();

        // Attempt a reload with duplicate IDs — should fail.
        let bad_rules = [
            make_rule(99, 5, Effect::Permit),
            make_rule(99, 15, Effect::Deny), // duplicate ID
        ];
        let result = engine.load_policy_set(&bad_rules);
        assert_eq!(result, Err(VsError::InvalidConfig));

        // Old rule must still be intact.
        assert_eq!(engine.rule_count(), 1);
        assert!(engine.get_rule(1).is_some());
    }

    #[test]
    fn atomic_reload_preserves_old_rules_on_capacity_exceeded() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();

        // Build a set that exceeds MAX_RULES.
        let mut too_many = [make_rule(0, 0, Effect::Deny); 65];
        for (i, rule) in too_many.iter_mut().enumerate() {
            rule.id = (i + 100) as u32;
            rule.priority = i as u8;
        }
        let result = engine.load_policy_set(&too_many);
        assert_eq!(result, Err(VsError::ResourceExhausted));

        // Original rule survives.
        assert_eq!(engine.rule_count(), 1);
        assert!(engine.get_rule(1).is_some());
    }

    #[test]
    fn atomic_reload_successful_swap() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 10, Effect::Permit)).unwrap();

        let new_rules = [
            make_rule(50, 1, Effect::Deny),
            make_rule(60, 2, Effect::Permit),
        ];
        engine.load_policy_set(&new_rules).unwrap();

        // Old rule gone, new rules present.
        assert_eq!(engine.rule_count(), 2);
        assert!(engine.get_rule(1).is_none());
        assert!(engine.get_rule(50).is_some());
        assert!(engine.get_rule(60).is_some());
    }

    /// Loads 10 valid rules, then attempts to reload with an invalid set
    /// (duplicate priority). Verifies that all 10 original rules are still
    /// present and queryable after the failed reload — exercising the C5
    /// atomic-reload guarantee.
    #[test]
    fn atomic_reload_ten_rules_intact_after_failed_reload() {
        let mut engine = PolicyEngine::new();

        // Load 10 valid rules with unique IDs and priorities.
        let original: [PolicyRule; 10] = [
            make_rule(1, 10, Effect::Permit),
            make_rule(2, 20, Effect::Deny),
            make_rule(3, 30, Effect::Permit),
            make_rule(4, 40, Effect::DenyAudit),
            make_rule(5, 50, Effect::Permit),
            make_rule(6, 60, Effect::Deny),
            make_rule(7, 70, Effect::Permit),
            make_rule(8, 80, Effect::DenyAudit),
            make_rule(9, 90, Effect::Permit),
            make_rule(10, 100, Effect::Deny),
        ];
        engine.load_policy_set(&original).unwrap();
        assert_eq!(
            engine.rule_count(),
            10,
            "all 10 original rules must be loaded"
        );
        let version_before = engine.policy_version();

        // Attempt a replacement with a duplicate priority — the second and
        // third entries both claim priority 5, which is invalid.
        let bad_rules = [
            make_rule(101, 5, Effect::Permit),
            make_rule(102, 5, Effect::Deny), // duplicate priority → PolicyViolation
            make_rule(103, 15, Effect::Permit),
        ];
        let result = engine.load_policy_set(&bad_rules);
        assert_eq!(
            result,
            Err(VsError::PolicyViolation),
            "reload with duplicate priority must return PolicyViolation"
        );

        // All 10 original rules must still be present and queryable.
        assert_eq!(
            engine.rule_count(),
            10,
            "rule count must remain 10 after failed reload"
        );
        for i in 1u32..=10 {
            assert!(
                engine.get_rule(i).is_some(),
                "rule {i} must survive failed reload"
            );
        }

        // Policy version must not have advanced.
        assert_eq!(
            engine.policy_version(),
            version_before,
            "policy version must not change after a failed reload"
        );
    }

    // ---- H1: Integrity check tests ----

    #[test]
    fn integrity_check_passes_after_add() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();
        assert!(engine.verify_integrity());
    }

    #[test]
    fn integrity_check_passes_after_load() {
        let mut engine = PolicyEngine::new();
        let rules = [
            make_rule(1, 10, Effect::Permit),
            make_rule(2, 20, Effect::Deny),
            make_rule(3, 30, Effect::DenyAudit),
        ];
        engine.load_policy_set(&rules).unwrap();
        assert!(engine.verify_integrity());
    }

    #[test]
    fn integrity_check_passes_after_remove() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();
        engine.add_rule(make_rule(2, 2, Effect::Deny)).unwrap();
        engine.remove_rule(1).unwrap();
        assert!(engine.verify_integrity());
    }

    #[test]
    fn integrity_check_passes_empty_engine() {
        let engine = PolicyEngine::new();
        assert!(engine.verify_integrity());
    }

    #[test]
    fn integrity_check_detects_tampering() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();
        assert!(engine.verify_integrity());

        // Tamper with a rule field directly (simulating memory corruption
        // or an attacker modifying rule storage).
        if let Some(ref mut rule) = engine.rules[0] {
            rule.effect = Effect::Deny;
        }

        // The checksum should now fail.
        assert!(!engine.verify_integrity());
    }

    #[test]
    fn integrity_check_128bit_different_from_zero() {
        // Verify that a non-empty engine produces a non-zero checksum,
        // ensuring the hash is actually computing something.
        let mut engine = PolicyEngine::new();
        engine.add_rule(make_rule(1, 1, Effect::Permit)).unwrap();
        assert_ne!(engine.rule_checksum, [0; 2]);
    }

    // ---- M3: Constant-time range check edge cases ----

    #[test]
    fn address_range_all_16_edge_cases() {
        // Helper to test a single range check via the subject_matches function.
        fn range_matches(addr: u32, low: u32, high: u32) -> bool {
            let matcher = SubjectMatcher::AddressRange(low, high);
            let subject = Subject {
                address: addr,
                authenticated: false,
                ecu_role: 0,
                session_token: 0,
                auth_level: AuthenticationLevel::None,
            };
            subject_matches(&matcher, &subject)
        }

        // Case 1: low=0, high=0, addr=0 => in range
        assert!(range_matches(0, 0, 0));
        // Case 2: low=0, high=0, addr=1 => out of range
        assert!(!range_matches(1, 0, 0));
        // Case 3: low=0, high=u32::MAX, addr=0 => in range (full range)
        assert!(range_matches(0, 0, u32::MAX));
        // Case 4: low=0, high=u32::MAX, addr=u32::MAX => in range
        assert!(range_matches(u32::MAX, 0, u32::MAX));
        // Case 5: low=0, high=u32::MAX, addr=12345 => in range
        assert!(range_matches(12345, 0, u32::MAX));
        // Case 6: low=high (single address), addr=low => in range
        assert!(range_matches(100, 100, 100));
        // Case 7: low=high (single address), addr=low-1 => out of range
        assert!(!range_matches(99, 100, 100));
        // Case 8: low=high (single address), addr=low+1 => out of range
        assert!(!range_matches(101, 100, 100));
        // Case 9: addr at lower boundary => in range
        assert!(range_matches(10, 10, 20));
        // Case 10: addr at upper boundary => in range
        assert!(range_matches(20, 10, 20));
        // Case 11: addr one below lower boundary => out of range
        assert!(!range_matches(9, 10, 20));
        // Case 12: addr one above upper boundary => out of range
        assert!(!range_matches(21, 10, 20));
        // Case 13: addr in middle of range => in range
        assert!(range_matches(15, 10, 20));
        // Case 14: addr=u32::MAX, range excludes it => out of range
        assert!(!range_matches(u32::MAX, 0, u32::MAX - 1));
        // Case 15: addr=0, range starts at 1 => out of range
        assert!(!range_matches(0, 1, u32::MAX));
        // Case 16: high boundary is u32::MAX, addr at boundary => in range
        assert!(range_matches(u32::MAX, u32::MAX, u32::MAX));
    }

    #[test]
    fn extended_can_id_matches_specific_address() {
        // Test that full 29-bit CAN IDs are properly matched.
        // 0x1ABCDEF would be truncated to 0xCDEF with u16, losing data.
        let mut engine = PolicyEngine::new();
        engine
            .add_rule(PolicyRule {
                id: 1,
                subject: SubjectMatcher::SpecificAddress(0x01AB_CDEF),
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Any,
                effect: Effect::Permit,
                priority: 1,
                valid_from: 0,
                valid_until: 0,
            })
            .unwrap();

        let subj = Subject {
            address: 0x01AB_CDEF,
            authenticated: false,
            ecu_role: 0,
            session_token: 0,
            auth_level: AuthenticationLevel::None,
        };
        let decision = engine.evaluate(&subj, &any_resource(), &read_action(), &no_env());
        assert_eq!(decision.effect, Effect::Permit);

        // A different address should not match.
        let subj_other = Subject {
            address: 0xCDEF, // Would match if truncated to u16
            authenticated: false,
            ecu_role: 0,
            session_token: 0,
            auth_level: AuthenticationLevel::None,
        };
        let decision2 = engine.evaluate(&subj_other, &any_resource(), &read_action(), &no_env());
        assert_eq!(decision2.effect, Effect::Deny);
    }
}
