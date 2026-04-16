# Changelog

All notable changes to `vs-diag-gateway` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.7.0]

### Fixed
- `restore_lockouts_from`: previous loop could pick an inactive slot before
  noticing an already-active slot for the same tester, producing duplicate
  lockout entries. Search for an existing active tester slot now takes
  precedence over picking an inactive slot, and a full table evicts the
  oldest `locked_until_us`.
- Corrected `#[deprecated(since = "...")]` on `NoOpPersistence` from the
  future-dated `0.8.0` to the current `0.7.0` release.
- `receive_uds_request` now performs the lockout check before clearing
  `recently_expired` or advancing `last_timestamp_us`, so a locked-out
  tester cannot perturb gateway state.

### Changed
- `BlockReason::GeneralProgrammingFailure` added and used for crypto-provider
  faults (RNG / HMAC) instead of `PolicyDenied`. NRC mapping reordered to
  group `SessionsFull` and `GeneralProgrammingFailure` under NRC `0x72`.
- `expire_sessions` no longer resets `recently_expired` on the fast path.
