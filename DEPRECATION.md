# Deprecation Policy

This document defines the Craton Shield deprecation and API stability policy.
The strict deprecation cycle described below takes full effect **from v1.0.0
onwards**. The project is currently at v0.7.0 and treats the pre-1.0 series
under a separate, looser rule set described immediately below.

## Applicability: pre-1.0 vs post-1.0

### Pre-1.0 (`0.x.y`)

Under Cargo's SemVer interpretation, `0.x.y` releases are pre-stable: a bump
of the MINOR component (`0.7` -> `0.8`) is permitted to contain breaking
changes. During the pre-1.0 series, Craton Shield therefore makes the
following commitments — and only these:

- The project **will attempt to deprecate-first when feasible**: when a
  replacement exists and the old item can be kept compilable without
  blocking other work, it will be marked `#[deprecated(...)]` in one MINOR
  release and removed in a later one.
- The project **does not guarantee a full deprecation cycle pre-1.0**.
  Some breaking changes (notably trait reshapes, ABI moves in `vs-ffi`,
  and security-driven API removals) will land directly on a MINOR bump
  without a prior `#[deprecated]` warning.
- **Every break, with or without a deprecation cycle, is documented in
  `CHANGELOG.md`** under the release that introduced it, together with
  the migration path.

Downstream callers on `0.x` should pin to an exact MINOR (`= "0.7"`, not
`"^0.7"`) if they cannot absorb a break on the next MINOR bump.

See also `core/docs/api-stability.md` for the broader pre-1.0 surface
policy (what counts as a break, ABI rules for `vs-ffi`, MSRV).

### Post-1.0 (`>= 1.0.0`)

From v1.0.0 onwards, the strict deprecation cycle in the rest of this
document applies in full: every removal is preceded by at least one full
MINOR cycle of `#[deprecated]`, and removals happen only on a MAJOR bump.

## Scope

This policy covers every item exported from a workspace member crate's
`pub` surface (functions, methods, structs, enums, traits, constants, type
aliases, and macros). It applies equally to crates in `core/`, `auto/`,
`embedded/`, and `industrial/`.

It does **not** cover:

- `pub(crate)` and lower visibilities — internal to the workspace.
- Items under `#[cfg(test)]` or `#[cfg(feature = "internal-…")]` — not
  shipped to downstream users.
- Items inside `fuzz/`, `benches/`, `examples/`, and `tests/` — not part
  of the published library surface.

## Versioning

Craton Shield follows Semantic Versioning (`MAJOR.MINOR.PATCH`):

- **PATCH** — bug fixes, documentation, internal refactors. No public API
  changes.
- **MINOR** — additive changes: new items, new variants on `#[non_exhaustive]`
  enums, new methods on traits with a default body, new features.
- **MAJOR** — breaking changes. Always preceded by at least one full minor
  cycle of deprecation (see below).

The MSRV (Minimum Supported Rust Version) follows the rules below and is
declared in `rust-toolchain.toml`. An MSRV bump is treated as a MINOR change.

## Deprecation cycle

1. **Mark.** The item is annotated with
   `#[deprecated(since = "X.Y.0", note = "…")]`. The `note` must point to a
   replacement (function, type, or migration guide section).
2. **Cycle.** The deprecated item remains compilable for at least one full
   MINOR cycle.  If it was marked in `vX.Y.0`, it cannot be removed before
   `vX.(Y+1).0`.
3. **Remove.** Removal happens in a MAJOR release and is recorded in
   `CHANGELOG.md` under the corresponding section.

The deprecation warning must compile cleanly under `#[deny(deprecated)]` in
downstream tests — the `note` must be informative enough that users can
migrate without consulting source.

## RFC requirement

Any change to the public API surface beyond bug fixes requires an RFC. The
RFC must:

1. Live as a pull request to this repository.
2. Describe the motivation, alternatives considered, and migration impact.
3. List every affected crate, item path, and downstream caller pattern.
4. Be approved by at least one maintainer per `MAINTAINERS.md`.

Trivial additive changes (a new method on an existing struct) may be merged
without an RFC at maintainer discretion. Anything that changes existing
signatures, removes items, or alters semantic behavior requires the full
process.

## Stable API surface

Each library crate exposes its v1.0 stable API in a clearly demarcated
section at the top of `src/lib.rs` titled "Public API (v1.0 stable)".
Items inside that section are governed by this policy. Items outside it
are either re-exports from another workspace crate (governed there) or
internal helpers that happen to be `pub` for documentation reasons.

## `cargo-semver-checks`

CI runs `cargo semver-checks check-release` on every pull request to detect
unintentional breaking changes. See `.github/workflows/semver.yml`.

A red `semver-check` status blocks merging into `main` unless the PR is
explicitly labelled `breaking-change` and targets the next MAJOR release
branch.

## Items removed in v1.0.0

The following items were marked deprecated during the v0.7 / v0.8 cycle and
are removed in v1.0.0:

- `vs_crypto::NonceCounter::last_counter_value` — use
  `NonceCounter::counter_for_persistence`.
- `vs_can_monitor::CanMonitor::new_with_replay_key` — use
  `CanMonitor::new(replay_key)`.
- `vs_diag_gateway::NoOpPersistence` — fail-closed stub; provide a real
  `AuditPersistence` implementation.
- `vs_autosar::NoOpSomeIpAuth` — fail-closed stub; provide a real
  `SomeIpAuthProvider`.
- `vs_runtime_auto::NoOpOtaSigner` — fail-closed stub; provide a real
  `OtaSignatureVerifier`.
- `vs_runtime_embedded::EmbeddedShield::core_mut`, the per-monitor
  `*_monitor_mut` accessors, and `drain_recent_alerts` were demoted to
  `#[cfg(test)]` so they no longer appear in the v1.0 public surface.
  Production callers must use the `configure_*` closures and
  `drain_recent_alerts_into` respectively.

Downstream code that depended on any of these items must migrate before
upgrading to v1.0.0.

## Items removed in future versions

Future removals are tracked in `CHANGELOG.md` under each release. New
deprecations land in the same release as the replacement.
