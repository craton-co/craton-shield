# vs-diag-gateway

> Part of [Craton Shield Auto](../../README.md) | [Architecture](../../docs/ARCHITECTURE.md)

UDS diagnostics gateway with SecurityAccess brute-force protection.

## Overview

This crate implements a UDS (Unified Diagnostic Services) gateway that
enforces SID-level allow-list policies, manages diagnostic sessions, and
provides brute-force lockout protection for SecurityAccess (0x27) requests.
All operations are logged to an internal audit ring buffer.

## Key Types

- `DiagGateway<C>` — central gateway managing sessions, policies, and lockout state
- `UdsPolicy` — SID allow-list with per-SID authentication requirements
- `DiagSession` — a single active diagnostic session with authentication state
- `DiagDecision` — gateway decision for a request (`Forward`, `Block`, `Challenge`)
- `BlockReason` — reason a request was blocked (`Unauthorized`, `LockedOut`, `SessionExpired`, `PolicyDenied`, `SessionsFull`)
- `SecurityChallenge` — random seed challenge for SecurityAccess
- `DiagAuditLog` — ring buffer of audit entries for diagnostic activity
- `AuditEntry` — a single audit log record with sequence number, SID, and decision

## Usage

```rust
use vs_diag_gateway::{DiagGateway, UdsPolicy, DiagDecision};

let mut policy = UdsPolicy::new();
policy.allow_sid(0x22); // ReadDataByIdentifier — no auth required
policy.require_auth_for_sid(0x31); // RoutineControl — auth required

let mut gw = DiagGateway::new(
    crypto,
    policy,
    5_000_000,  // 5 s session timeout
    10_000_000, // 10 s lockout duration
    0,          // HMAC key slot
);

let decision = gw.receive_uds_request(tester_addr, sid, &payload, timestamp_us);
match decision {
    DiagDecision::Forward => { /* relay to target ECU */ }
    DiagDecision::Block(reason) => { /* reject with NRC */ }
    DiagDecision::Challenge(challenge) => { /* send seed to tester */ }
}
```

## Feature Flags

See [core/docs/feature-flags.md](../../core/docs/feature-flags.md) for the full workspace feature reference.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
