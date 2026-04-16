# Changelog

All notable changes to `vs-policy-engine` are documented in this file.

## [0.7.0]

- `clear_rules` now explicitly increments `policy_version`, making the clear
  observable independent of any subsequent reload.
- `explain_decision` paths now apply the same action-type candidate bitmask
  used by `evaluate`, cutting rule scans in mixed-action sets by ~50%.
- `evaluate_deny_overrides` / `evaluate_permit_overrides` iterate the
  candidate bitmask in O(popcount) instead of scanning every slot.
- `PermitOverrides` no longer allocates a 1 KB `[Option<u32>; 64]` per call
  for deny-audit tracking; uses a single `u64` bitmask instead.
- Documentation fixes: README example matches the current 4-arg `evaluate`
  signature; `FirstApplicable` references replaced with `FirstMatch`;
  README lists all three combining algorithms.
- Added `#![deny(missing_docs)]` and documented all public items.
- Cargo manifest: switched `vs-types` to `workspace = true` and enabled
  `all-features` on docs.rs.
