# Changelog

All notable changes to `vs-report-iso21434` will be documented in this file.

## [0.7.0]

- Adapt to `vs-evidence-envelope` API change: `Evidence::with_metadata` now
  takes a `Standard` argument; callers pass `Standard::Iso21434`.
- Add duplicate `threat_id` detection in `generate_tara`; duplicates now
  yield `Err(VsError::InvalidInput)` instead of silently shadowing.
- `generate_tara_from_catalog` now returns `Err(VsError::InvalidInput)` when
  `damage_count > damages.len()` instead of silently truncating.
- Counter accumulation uses `saturating_add` (defense-in-depth).
- `highest_risk()` short-circuits on `RiskLevel::Critical`.
- `TOOL_VERSION` remains `"vs-iso21434/0.7"`, matching the workspace
  version.
