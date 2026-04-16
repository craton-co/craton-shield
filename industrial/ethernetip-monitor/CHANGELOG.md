# Changelog

All notable changes to `vs-ethernetip-monitor` are documented in this file.

## [0.7.0]

### Security

- Reject `session_handle == 0` on any encapsulation command other than
  `REGISTER_SESSION` (`0x0065`). The reserved sentinel handle is invalid for
  data-plane traffic per the EtherNet/IP spec; frames carrying it are now
  denied with `AlertCode::UnknownSession` and severity `High`. Previously
  such frames were silently accepted in permissive mode, allowing an
  attacker to forge `UnregisterSession`, `SendRRData`, and `SendUnitData`
  against the no-session sentinel and bypass per-session controls.
  `REGISTER_SESSION` with handle `0` is still processed normally (it is
  the on-wire norm — the server assigns the real handle in the reply).

### Changed

- Session-table LRU eviction now picks the entry with the oldest
  `last_activity_us` rather than the oldest `created_us`, matching the
  semantics already used by `expire_sessions`. Long-running active
  sessions are no longer evicted in favour of recently idle ones.
- `register_session` is now single-pass (mirrors `rate_check`).
- Strict-mode session lookup combines the touch and known-check into a
  single scan of the session table.
- README corrected: the rate-limit table uses LRU eviction (oldest
  bucket dropped, new key admitted), not fail-closed. Use
  `new_strict()` for fail-closed behaviour on unknown sessions or
  unmatched commands.
