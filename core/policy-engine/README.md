# vs-policy-engine

Security policy evaluation engine for alert routing and response.

## Overview

This crate implements an XACML-lite policy engine for evaluating security
decisions across the Craton Shield platform. Rules match on subject, resource,
and action dimensions and produce permit, deny, or deny-with-audit effects.
Rules are evaluated in priority order with first-match semantics.

## Key Types

- `PolicyEngine` — evaluates access requests against a prioritized rule table
- `PolicyRule` — a single rule with subject, resource, and action matchers plus effect
- `Effect` — rule outcome (Permit, Deny, DenyAudit)
- `SubjectMatcher` — matches by identity (Any, AuthenticatedTester, SpecificAddress, EcuRole)
- `ResourceMatcher` — matches by target (Any, BusId, DiagnosticService, FirmwareRegion)
- `ActionMatcher` — matches by operation (Any, Read, Write, Execute, Transmit, DiagnosticRequest)

## Usage

```rust
use vs_policy_engine::{PolicyEngine, PolicyRule, Effect, SubjectMatcher,
                       ResourceMatcher, ActionMatcher};

let mut engine = PolicyEngine::new();
engine.add_rule(PolicyRule {
    id: 1, priority: 10, effect: Effect::Deny,
    subject: SubjectMatcher::Any,
    resource: ResourceMatcher::DiagnosticService(0x34),
    action: ActionMatcher::Any,
})?;
let decision = engine.evaluate(&subject, &resource, &action);
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
