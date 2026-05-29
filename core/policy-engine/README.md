# vs-policy-engine

Security policy evaluation engine for alert routing and response.

## Overview

This crate implements an XACML-lite policy engine for evaluating security
decisions across the Craton Shield platform. Rules match on subject, resource,
and action dimensions and produce permit, deny, or deny-with-audit effects.
Rules are evaluated in priority order. The engine supports three rule-combining
algorithms:

- `FirstMatch` (default): the first matching rule determines the decision
- `DenyOverrides`: any matching Deny/DenyAudit overrides all Permits
- `PermitOverrides`: any matching Permit overrides all Denies

## Key Types

- `PolicyEngine` — evaluates access requests against a prioritized rule table
- `PolicyRule` — a single rule with subject, resource, and action matchers plus effect
- `Effect` — rule outcome (Permit, Deny, DenyAudit)
- `CombiningAlgorithm` — rule combining strategy (FirstMatch, DenyOverrides, PermitOverrides)
- `SubjectMatcher` — matches by identity (Any, AuthenticatedTester, SpecificAddress, EcuRole)
- `ResourceMatcher` — matches by target (Any, BusId, DiagnosticService, FirmwareRegion)
- `ActionMatcher` — matches by operation (Any, Read, Write, Execute, Transmit, DiagnosticRequest)

## Usage

```rust
use vs_policy_engine::{
    Action, ActionMatcher, ActionType, AuthenticationLevel, Effect, Environment,
    PolicyEngine, PolicyRule, Resource, ResourceMatcher, Subject, SubjectMatcher,
};

let mut engine = PolicyEngine::new();
engine.add_rule(PolicyRule {
    id: 1,
    priority: 10,
    effect: Effect::Deny,
    subject: SubjectMatcher::Any,
    resource: ResourceMatcher::DiagnosticService(0x34),
    action: ActionMatcher::Any,
    valid_from: 0,
    valid_until: 0,
})?;

let subject = Subject {
    address: 0x7E0,
    authenticated: false,
    ecu_role: 0,
    session_token: 0,
    auth_level: AuthenticationLevel::None,
};
let resource = Resource {
    bus_type: None,
    bus_id: None,
    service_id: Some(0x34),
    firmware_region: None,
};
let action = Action { action_type: ActionType::Read };
let env = Environment { timestamp_us: 0 };

let decision = engine.evaluate(&subject, &resource, &action, &env);
```

## License

Apache-2.0. See [LICENSE](LICENSE).
