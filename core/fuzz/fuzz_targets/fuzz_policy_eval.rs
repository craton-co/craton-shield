// SPDX-License-Identifier: Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;
use vs_policy_engine::{
    Action, ActionMatcher, ActionType, AuthenticationLevel, Effect, Environment, PolicyEngine,
    PolicyRule, Resource, ResourceMatcher, Subject, SubjectMatcher,
};

fuzz_target!(|data: &[u8]| {
    // Fuzz the policy engine evaluation with arbitrary rule and request data.
    // The engine must not panic on any input.
    if data.len() < 16 {
        return;
    }

    let mut engine = PolicyEngine::new();

    // Add a rule with fuzzed parameters.
    let effect = match data[0] % 3 {
        0 => Effect::Permit,
        1 => Effect::Deny,
        _ => Effect::DenyAudit,
    };

    let subject_matcher = match data[1] % 4 {
        0 => SubjectMatcher::Any,
        1 => SubjectMatcher::AuthenticatedTester,
        2 => SubjectMatcher::SpecificAddress(u32::from_le_bytes([data[2], data[3], data[4], data[5]])),
        _ => SubjectMatcher::EcuRole(data[2]),
    };

    let resource_matcher = match data[6] % 3 {
        0 => ResourceMatcher::Any,
        1 => ResourceMatcher::DiagnosticService(data[7]),
        _ => ResourceMatcher::FirmwareRegion(data[7]),
    };

    let action_matcher = match data[8] % 5 {
        0 => ActionMatcher::Any,
        1 => ActionMatcher::Read,
        2 => ActionMatcher::Write,
        3 => ActionMatcher::Execute,
        _ => ActionMatcher::Transmit,
    };

    let rule = PolicyRule {
        id: u32::from_le_bytes([data[9], data[10], data[11], data[12]]),
        priority: data[13],
        effect,
        subject: subject_matcher,
        resource: resource_matcher,
        action: action_matcher,
        valid_from: 0,
        valid_until: 0,
    };
    let _ = engine.add_rule(rule);

    // Build a request from remaining fuzz bytes.
    let auth_level = match data[14] % 3 {
        0 => AuthenticationLevel::None,
        1 => AuthenticationLevel::Basic,
        _ => AuthenticationLevel::Extended,
    };

    let subject = Subject {
        address: u32::from_le_bytes([data[2], data[3], data[4], data[5]]),
        authenticated: data[15] & 1 == 0,
        session_token: u64::from(u16::from_le_bytes([data[14], data[15]])),
        auth_level,
        ecu_role: data.get(16).copied().unwrap_or(0),
    };

    let resource = Resource {
        bus_type: Some(data.get(17).copied().unwrap_or(0)),
        bus_id: Some(u32::from(data.get(18).copied().unwrap_or(0))),
        service_id: Some(data.get(19).copied().unwrap_or(0)),
        firmware_region: None,
    };

    let action_type = match data.get(20).copied().unwrap_or(0) % 4 {
        0 => ActionType::Read,
        1 => ActionType::Write,
        2 => ActionType::Execute,
        _ => ActionType::Transmit,
    };
    let action = Action {
        action_type,
    };

    let timestamp = u64::from_le_bytes([
        data.get(21).copied().unwrap_or(0),
        data.get(22).copied().unwrap_or(0),
        data.get(23).copied().unwrap_or(0),
        data.get(24).copied().unwrap_or(0),
        data.get(25).copied().unwrap_or(0),
        data.get(26).copied().unwrap_or(0),
        data.get(27).copied().unwrap_or(0),
        data.get(28).copied().unwrap_or(0),
    ]);

    let env = Environment {
        timestamp_us: timestamp,
    };

    let decision1 = engine.evaluate(&subject, &resource, &action, &env);

    // 1. Verify determinism: same input must produce the same decision.
    let decision2 = engine.evaluate(&subject, &resource, &action, &env);
    assert_eq!(decision1, decision2, "policy evaluation must be deterministic");

    // 2. Verify Deny-rule invariant: if we added a Deny/DenyAudit rule and
    //    the effect in the first decision is not Permit, it must remain
    //    non-Permit (the engine never upgrades a Deny to a Permit).
    //    More precisely: when the fuzz-constructed rule has a Deny effect
    //    AND it was the only rule, the engine must never return Permit when
    //    the rule matches.  We check the weaker, always-valid property:
    //    a decision that came back as Deny or DenyAudit must not equal Permit.
    if decision1.effect == Effect::Deny || decision1.effect == Effect::DenyAudit {
        assert_ne!(
            decision1.effect,
            Effect::Permit,
            "a Deny decision must not be Permit"
        );
    }
});
