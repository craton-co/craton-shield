# Changelog

All notable changes to `vs-key-manager` are documented here. This crate
follows the workspace version (pre-1.0; see ROADMAP for stability commitment).

## [0.7.0]

### Changed

- **Behavior change for fail-closed callers**: `provision_key`, `generate_key`,
  `rotate_key`, and `revoke_key` now pre-check audit-ring headroom via
  `audit_has_headroom()` before mutating slot state. Previously, a
  `ResourceExhausted` error from the post-commit audit append could leave
  the slot already updated (or zeroized) with no audit record. Callers now
  observe a clean refusal with state unchanged.

### Added

- `KeyManager::audit_has_headroom()` — public predicate for fail-closed
  callers to perform their own pre-flight checks.
- O(1) cached `active_count`; `key_capacity()` no longer scans all slots.

### Fixed

- `keym_finalize` no longer collapses every slot's `metadata.key_id` to
  `KeyId(0)`. The slot-index == key_id invariant is preserved after
  finalize.
- Bench `audit_append_after_wrap` now uses non-uniform key material so
  `validate_key_material` accepts it.
- README example rewritten to compile against the real API and added
  as a doc-test on `KeyManager::new`.

### Docs

- `tick()` documents that audit-emit failures during expiry are dropped.
- All public enum variants and `KeyMetadata` / `AuditEntry` fields are
  documented (`#![deny(missing_docs)]`).
