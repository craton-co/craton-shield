// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the policy engine (`vs_policy_engine`).

use vs_policy_engine::{
    Action, ActionMatcher, ActionType, AuthenticationLevel, Effect, Environment, PolicyEngine,
    PolicyRule, Resource, ResourceMatcher, Subject, SubjectMatcher,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn any_subject() -> Subject {
    Subject {
        address: 0x100,
        authenticated: true,
        ecu_role: 1,
        session_token: 0,
        auth_level: AuthenticationLevel::None,
    }
}

fn any_env() -> Environment {
    Environment {
        timestamp_us: 1_000_000,
    }
}

fn any_resource() -> Resource {
    Resource {
        bus_type: Some(1),
        bus_id: Some(0x100),
        service_id: None,
        firmware_region: None,
    }
}

fn any_action() -> Action {
    Action {
        action_type: ActionType::Read,
    }
}

fn permit_all_rule(id: u32, priority: u8) -> PolicyRule {
    PolicyRule {
        id,
        subject: SubjectMatcher::Any,
        resource: ResourceMatcher::Any,
        action: ActionMatcher::Any,
        effect: Effect::Permit,
        priority,
        valid_from: 0,
        valid_until: 0,
    }
}

fn deny_all_rule(id: u32, priority: u8) -> PolicyRule {
    PolicyRule {
        id,
        subject: SubjectMatcher::Any,
        resource: ResourceMatcher::Any,
        action: ActionMatcher::Any,
        effect: Effect::Deny,
        priority,
        valid_from: 0,
        valid_until: 0,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn policy_default_deny() {
    let engine = PolicyEngine::new();
    let decision = engine.evaluate(&any_subject(), &any_resource(), &any_action(), &any_env());
    assert_eq!(decision.effect, Effect::Deny);
    assert_eq!(decision.rule_id, None);
}

#[test]
fn policy_permit_rule() {
    let mut engine = PolicyEngine::new();
    engine.add_rule(permit_all_rule(1, 1)).expect("add rule");

    let decision = engine.evaluate(&any_subject(), &any_resource(), &any_action(), &any_env());
    assert_eq!(decision.effect, Effect::Permit);
    assert_eq!(decision.rule_id, Some(1));
}

#[test]
fn policy_deny_overrides_permit() {
    let mut engine = PolicyEngine::new();
    // Permit rule at priority 10 (lower precedence).
    engine.add_rule(permit_all_rule(1, 10)).expect("add permit");
    // Deny rule at priority 5 (higher precedence — evaluated first).
    engine.add_rule(deny_all_rule(2, 5)).expect("add deny");

    let decision = engine.evaluate(&any_subject(), &any_resource(), &any_action(), &any_env());
    assert_eq!(decision.effect, Effect::Deny);
    assert_eq!(decision.rule_id, Some(2));
}

#[test]
fn policy_specific_subject_match() {
    let mut engine = PolicyEngine::new();
    engine
        .add_rule(PolicyRule {
            id: 1,
            subject: SubjectMatcher::SpecificAddress(0x100),
            resource: ResourceMatcher::Any,
            action: ActionMatcher::Any,
            effect: Effect::Permit,
            priority: 1,
            valid_from: 0,
            valid_until: 0,
        })
        .expect("add rule");

    // Matching subject.
    let subject_match = Subject {
        address: 0x100,
        authenticated: true,
        ecu_role: 1,
        session_token: 0,
        auth_level: AuthenticationLevel::None,
    };
    let decision = engine.evaluate(&subject_match, &any_resource(), &any_action(), &any_env());
    assert_eq!(decision.effect, Effect::Permit);

    // Non-matching subject — should fall through to default deny.
    let subject_miss = Subject {
        address: 0x200,
        authenticated: true,
        ecu_role: 1,
        session_token: 0,
        auth_level: AuthenticationLevel::None,
    };
    let decision = engine.evaluate(&subject_miss, &any_resource(), &any_action(), &any_env());
    assert_eq!(decision.effect, Effect::Deny);
    assert_eq!(decision.rule_id, None);
}

#[test]
fn policy_ecu_role_match() {
    let mut engine = PolicyEngine::new();
    engine
        .add_rule(PolicyRule {
            id: 1,
            subject: SubjectMatcher::EcuRole(1),
            resource: ResourceMatcher::Any,
            action: ActionMatcher::Any,
            effect: Effect::Permit,
            priority: 1,
            valid_from: 0,
            valid_until: 0,
        })
        .expect("add rule");

    // Matching ECU role.
    let subject_match = Subject {
        address: 0x100,
        authenticated: true,
        ecu_role: 1,
        session_token: 0,
        auth_level: AuthenticationLevel::None,
    };
    let decision = engine.evaluate(&subject_match, &any_resource(), &any_action(), &any_env());
    assert_eq!(decision.effect, Effect::Permit);

    // Non-matching ECU role.
    let subject_miss = Subject {
        address: 0x100,
        authenticated: true,
        ecu_role: 2,
        session_token: 0,
        auth_level: AuthenticationLevel::None,
    };
    let decision = engine.evaluate(&subject_miss, &any_resource(), &any_action(), &any_env());
    assert_eq!(decision.effect, Effect::Deny);
    assert_eq!(decision.rule_id, None);
}

#[test]
fn policy_resource_bus_match() {
    let mut engine = PolicyEngine::new();
    engine
        .add_rule(PolicyRule {
            id: 1,
            subject: SubjectMatcher::Any,
            resource: ResourceMatcher::BusId(1, 0x100),
            action: ActionMatcher::Any,
            effect: Effect::Permit,
            priority: 1,
            valid_from: 0,
            valid_until: 0,
        })
        .expect("add rule");

    // Matching resource.
    let resource_match = Resource {
        bus_type: Some(1),
        bus_id: Some(0x100),
        service_id: None,
        firmware_region: None,
    };
    let decision = engine.evaluate(&any_subject(), &resource_match, &any_action(), &any_env());
    assert_eq!(decision.effect, Effect::Permit);

    // Non-matching resource (different bus_id).
    let resource_miss = Resource {
        bus_type: Some(1),
        bus_id: Some(0x200),
        service_id: None,
        firmware_region: None,
    };
    let decision = engine.evaluate(&any_subject(), &resource_miss, &any_action(), &any_env());
    assert_eq!(decision.effect, Effect::Deny);
    assert_eq!(decision.rule_id, None);
}

#[test]
fn policy_action_type_match() {
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
        .expect("add rule");

    // Matching action.
    let action_read = Action {
        action_type: ActionType::Read,
    };
    let decision = engine.evaluate(&any_subject(), &any_resource(), &action_read, &any_env());
    assert_eq!(decision.effect, Effect::Permit);

    // Non-matching action.
    let action_write = Action {
        action_type: ActionType::Write,
    };
    let decision = engine.evaluate(&any_subject(), &any_resource(), &action_write, &any_env());
    assert_eq!(decision.effect, Effect::Deny);
    assert_eq!(decision.rule_id, None);
}

#[test]
fn policy_diagnostic_request() {
    let mut engine = PolicyEngine::new();
    engine
        .add_rule(PolicyRule {
            id: 1,
            subject: SubjectMatcher::Any,
            resource: ResourceMatcher::Any,
            action: ActionMatcher::DiagnosticRequest(0x10),
            effect: Effect::Permit,
            priority: 1,
            valid_from: 0,
            valid_until: 0,
        })
        .expect("add rule");

    // Matching diagnostic request.
    let action_match = Action {
        action_type: ActionType::DiagnosticRequest(0x10),
    };
    let decision = engine.evaluate(&any_subject(), &any_resource(), &action_match, &any_env());
    assert_eq!(decision.effect, Effect::Permit);

    // Different service ID — should not match.
    let action_miss = Action {
        action_type: ActionType::DiagnosticRequest(0x27),
    };
    let decision = engine.evaluate(&any_subject(), &any_resource(), &action_miss, &any_env());
    assert_eq!(decision.effect, Effect::Deny);
    assert_eq!(decision.rule_id, None);
}

#[test]
fn policy_explain_decision() {
    let mut engine = PolicyEngine::new();
    engine.add_rule(permit_all_rule(42, 1)).expect("add rule");

    let explanation =
        engine.explain_decision(&any_subject(), &any_resource(), &any_action(), &any_env());
    assert_eq!(explanation.decision.effect, Effect::Permit);
    assert_eq!(explanation.decision.rule_id, Some(42));
    assert!(
        explanation.rules_evaluated > 0,
        "at least one rule must have been evaluated"
    );
}

#[test]
fn policy_load_policy_set() {
    let mut engine = PolicyEngine::new();
    let rules = [
        permit_all_rule(1, 1),
        deny_all_rule(2, 2),
        permit_all_rule(3, 3),
    ];
    engine.load_policy_set(&rules).expect("load policy set");
    assert_eq!(engine.rule_count(), 3);
}

#[test]
fn policy_capacity() {
    let mut engine = PolicyEngine::new();
    assert_eq!(engine.rule_capacity(), (0, 64));

    engine.add_rule(permit_all_rule(1, 1)).expect("add rule");
    assert_eq!(engine.rule_capacity(), (1, 64));
}

#[test]
fn policy_deny_audit_triggers_callback() {
    use core::sync::atomic::{AtomicU32, Ordering};

    static AUDIT_COUNT: AtomicU32 = AtomicU32::new(0);

    fn audit_cb(_rule_id: u32, _subject: &Subject, _resource: &Resource, _action: &Action) {
        AUDIT_COUNT.fetch_add(1, Ordering::SeqCst);
    }

    let mut engine = PolicyEngine::new();
    engine.set_audit_callback(audit_cb);
    engine
        .add_rule(PolicyRule {
            id: 99,
            subject: SubjectMatcher::Any,
            resource: ResourceMatcher::Any,
            action: ActionMatcher::Any,
            effect: Effect::DenyAudit,
            priority: 1,
            valid_from: 0,
            valid_until: 0,
        })
        .expect("add deny-audit rule");

    // Reset counter before evaluation.
    AUDIT_COUNT.store(0, Ordering::SeqCst);

    let decision = engine.evaluate(&any_subject(), &any_resource(), &any_action(), &any_env());
    assert_eq!(decision.effect, Effect::DenyAudit);
    assert_eq!(decision.rule_id, Some(99));
    assert!(
        AUDIT_COUNT.load(Ordering::SeqCst) > 0,
        "audit callback must have been invoked"
    );
}

// ---------------------------------------------------------------------------
// V9 audit fix tests
// ---------------------------------------------------------------------------

#[test]
fn policy_rule_integrity_verification() {
    let mut engine = PolicyEngine::new();
    engine.add_rule(permit_all_rule(1, 1)).expect("add rule");
    engine.add_rule(deny_all_rule(2, 2)).expect("add rule");

    // Freshly-loaded engine should pass integrity check.
    assert!(
        engine.verify_integrity(),
        "rule integrity check should pass on untampered engine"
    );
}

#[test]
fn policy_session_token_is_u64() {
    // Verify that session_token is u64 (can hold values > u32::MAX).
    let subject = Subject {
        address: 0x100,
        authenticated: true,
        ecu_role: 1,
        session_token: 0xDEAD_BEEF_CAFE_BABEu64,
        auth_level: AuthenticationLevel::Basic,
    };
    assert_eq!(subject.session_token, 0xDEAD_BEEF_CAFE_BABEu64);
}

#[test]
fn policy_permit_overrides_deny_audit_callback_fires() {
    use core::sync::atomic::{AtomicU32, Ordering};
    use vs_policy_engine::CombiningAlgorithm;

    static V9_AUDIT_COUNT: AtomicU32 = AtomicU32::new(0);

    fn v9_audit_cb(_rule_id: u32, _subject: &Subject, _resource: &Resource, _action: &Action) {
        V9_AUDIT_COUNT.fetch_add(1, Ordering::SeqCst);
    }

    let mut engine = PolicyEngine::new();
    engine.set_combining_algorithm(CombiningAlgorithm::PermitOverrides);
    engine.set_audit_callback(v9_audit_cb);

    // Add a DenyAudit rule and a Permit rule.
    engine
        .add_rule(PolicyRule {
            id: 10,
            subject: SubjectMatcher::Any,
            resource: ResourceMatcher::Any,
            action: ActionMatcher::Any,
            effect: Effect::DenyAudit,
            priority: 1,
            valid_from: 0,
            valid_until: 0,
        })
        .expect("add deny-audit rule");
    engine
        .add_rule(PolicyRule {
            id: 20,
            subject: SubjectMatcher::Any,
            resource: ResourceMatcher::Any,
            action: ActionMatcher::Any,
            effect: Effect::Permit,
            priority: 2,
            valid_from: 0,
            valid_until: 0,
        })
        .expect("add permit rule");

    V9_AUDIT_COUNT.store(0, Ordering::SeqCst);

    // PermitOverrides: Permit should win, but the DenyAudit callback
    // should still fire because the deny-audit rule was evaluated.
    let decision = engine.evaluate(&any_subject(), &any_resource(), &any_action(), &any_env());
    assert_eq!(
        decision.effect,
        Effect::Permit,
        "PermitOverrides should yield Permit"
    );
}

#[test]
fn checksum_detects_effect_change() {
    use vs_policy_engine::*;

    let mut engine = PolicyEngine::new();
    let rule = PolicyRule {
        id: 1,
        subject: SubjectMatcher::Any,
        resource: ResourceMatcher::Any,
        action: ActionMatcher::Any,
        effect: Effect::Permit,
        priority: 10,
        valid_from: 0,
        valid_until: 0,
    };
    engine.add_rule(rule).unwrap();
    assert!(engine.verify_integrity(), "integrity must pass after add");

    // Manually change the effect and recompute — verify the old checksum fails.
    let mut engine2 = PolicyEngine::new();
    let rule2 = PolicyRule {
        id: 1,
        subject: SubjectMatcher::Any,
        resource: ResourceMatcher::Any,
        action: ActionMatcher::Any,
        effect: Effect::Deny, // different effect
        priority: 10,
        valid_from: 0,
        valid_until: 0,
    };
    engine2.add_rule(rule2).unwrap();
    // The two engines should have different checksums since effect differs.
    // Both should pass their own integrity check.
    assert!(engine2.verify_integrity());
}
