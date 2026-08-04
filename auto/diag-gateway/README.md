# vs-diag-gateway

> Part of [Craton Shield Auto](../../README.md) | [Architecture](../../core/docs/architecture.md)

UDS diagnostics gateway with SecurityAccess brute-force protection.

## Overview

This crate implements a UDS (Unified Diagnostic Services) gateway that
enforces SID-level allow-list policies, manages diagnostic sessions, and
provides brute-force lockout protection for SecurityAccess (0x27) requests.
All operations are logged to an internal audit ring buffer.

## Key Types

- `DiagGateway<C>` — central gateway managing sessions, policies, and lockout state
- `UdsPolicy` — SID allow-list with per-SID authentication requirements and per-SID minimum `SecurityAccess` level
- `DiagSession` — a single active diagnostic session with authentication state
- `DiagDecision` — gateway decision for a request (`Forward`, `Block`, `Challenge`)
- `BlockReason` — reason a request was blocked (`Unauthorized`, `LockedOut`, `SessionExpired`, `PolicyDenied`, `SessionsFull`, `SecurityAccessDenied`, `GeneralProgrammingFailure`)
- `SecurityChallenge` — random seed challenge for SecurityAccess
- `DiagAuditLog` — ring buffer of audit entries for diagnostic activity
- `AuditEntry` — a single audit log record with sequence number, SID, and decision
- `LockoutEntry` — exportable lockout-table row for persistence/restore
- `AuditPersistence` — trait for non-volatile audit + lockout storage

## Additional APIs

- `DiagGateway::expire_sessions_proactive(ts_us)` — call from a periodic
  tick to evict idle sessions without processing a UDS request. Useful
  to free slot capacity when no new traffic arrives.
- `DiagGateway::set_persistence_callbacks(persist_entry, persist_lockout)`
  — install function-pointer callbacks invoked on every audit entry and
  on every lockout-state change. Lets a platform integrator wire flash
  or EEPROM persistence without adding a generic parameter.
- `DiagGateway::restore_lockouts_from(&[LockoutEntry]) -> usize` — repopulate
  the in-memory lockout table after an ECU reset. Active entries for the
  same tester are merged (no duplicates) and inactive slots are filled
  next; if the table is full, the entry with the oldest `locked_until_us`
  is evicted.
- Exponential-backoff lockout — after `LOCKOUT_THRESHOLD` failed
  `SecurityAccess` attempts, the tester is locked out for `lockout_duration_us`.
  Each successive lockout doubles the duration, capped at 8x base (generation 3).
  A successful authentication clears the counter and generation.
- Seed-request rate limit — consecutive seed requests from the same
  tester are rate-limited to one per `MIN_SEED_INTERVAL_US` (100 ms) to
  blunt aggressive probing.
- NRC mapping — `BlockReason::nrc()` translates a block reason to the
  ISO 14229 Negative Response Code (`0x33` security access denied,
  `0x37` required time delay not expired, `0x24` request sequence error,
  `0x11` service not supported, `0x72` general programming failure).
- `BlockReason::SecurityAccessDenied` — emitted when a session's current
  `security_level` is below the per-SID minimum configured via
  `UdsPolicy::set_min_security_level`. Maps to NRC `0x33`.

## Usage

```rust,ignore
use vs_diag_gateway::{DiagGateway, UdsPolicy, DiagDecision};
use vs_crypto::KeyId; // KeyId is re-exported from vs-crypto, not vs-types

// `crypto` is any type implementing `vs_crypto::CryptoProvider`. In tests
// the `mock-hsm` feature of `vs-crypto` provides `SoftwareCryptoProvider`;
// production deployments pass their HSM-backed provider.
let crypto = make_crypto_provider();

let mut policy = UdsPolicy::new();
policy.allow_sid(0x22); // ReadDataByIdentifier — no auth required
policy.require_auth_for_sid(0x31); // RoutineControl — auth required
// `set_min_security_level` returns `Result` — it rejects SID 0x10/0x27.
policy.set_min_security_level(0x22, 1).expect("0x22 accepts a min level");

let mut gw = DiagGateway::new(
    crypto,
    policy,
    5_000_000,   // 5 s session timeout
    10_000_000,  // 10 s lockout duration
    KeyId(0),    // HMAC key slot — newtype-wrapped
);

// `tester_addr`, `sid`, `payload`, and `timestamp_us` come from the
// transport layer (CAN / DoIP). `timestamp_us` must be a single monotonic
// microsecond clock shared by all callers.
let decision = gw.receive_uds_request(tester_addr, sid, &payload, timestamp_us);
match decision {
    DiagDecision::Forward => { /* relay to target ECU */ }
    DiagDecision::Block(reason) => { /* reject with NRC reason.nrc() */ }
    DiagDecision::Challenge(challenge) => { /* send challenge.seed to tester */ }
}
```

## Feature Flags

See [core/docs/feature-flags.md](../../core/docs/feature-flags.md) for the full workspace feature reference.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
