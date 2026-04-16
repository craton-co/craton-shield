# API Stability & Versioning Policy

> Craton Shield 0.7.0

## Versioning Scheme

Craton Shield follows [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR** (1.0, 2.0): Breaking changes to public API or ABI
- **MINOR** (0.7, 0.8): New features, backward-compatible
- **PATCH** (0.6.1): Bug fixes, security patches, no API changes

All workspace crates share a single version number. A breaking change in any crate bumps the entire workspace.

## Current Status: Pre-1.0

During the `0.x` series, minor versions may include breaking changes. The API is not yet stable. We aim for 1.0 after completing ISO 21434 gap analysis and the first external security audit.

### What counts as a breaking change

| Category | Breaking | Non-breaking |
|----------|----------|--------------|
| Public struct fields | Remove or reorder | Add at end |
| Public enum variants | Remove | Add (with `#[non_exhaustive]`) |
| Trait methods | Remove, change signature | Add with default impl |
| Function parameters | Change type or count | Add optional parameter (new fn) |
| `#[repr(C)]` layout | Reorder, remove fields | Add fields at end |
| Feature flags | Remove | Add new flag |
| Error variants | Remove | Add new variant |
| MSRV | Lower is fine | Raise = breaking |

### ABI stability (`vs-ffi`)

The C header `include/cratonshield.h` defines the stable ABI surface. Changes to `vs-ffi` follow stricter rules:

- **Never** remove or reorder struct fields
- **Never** change function signatures in a patch release
- **Never** change enum discriminant values
- New fields go at the end of structs
- New functions get a version suffix if they replace existing ones

## Minimum Supported Rust Version (MSRV)

- **Current MSRV**: Rust 1.82 (stable)
- MSRV bumps are treated as minor-version changes (documented in CHANGELOG)
- CI tests against the MSRV in addition to latest stable

## Deprecation Policy

The authoritative deprecation rules — including the strict one-MINOR-release
deprecation cycle that applies from v1.0.0 onwards — live in
[`DEPRECATION.md`](../../DEPRECATION.md) at the workspace root. The summary
here describes the pre-1.0 working rules, which are deliberately looser to
match Cargo SemVer's treatment of `0.x.y` as pre-stable (see "Current Status:
Pre-1.0" above).

Pre-1.0 working rules:

1. Mark with `#[deprecated(since = "0.x.0", note = "Use new_fn instead")]`
   whenever a replacement is ready and the deprecation cycle is feasible.
2. Keep deprecated items for at least one MINOR release when practical;
   pre-1.0 we reserve the right to break on a MINOR bump without a prior
   deprecation cycle, but will document the break in CHANGELOG.md.
3. Remove in the next MINOR release pre-1.0, or in the next MAJOR release
   once the project has reached 1.0.
4. Document every removal in CHANGELOG.md under the release that performed
   it, with a migration note pointing at the replacement.

From v1.0.0 onwards, point (2) becomes a hard guarantee and point (3)
collapses to "removal happens only on a MAJOR bump" — see `DEPRECATION.md`
for the full post-1.0 cycle.

## Dependency Policy

- All dependencies are vetted via `cargo audit` and `deny.toml`
- Security-critical crates (crypto, zeroize, subtle) are pinned to exact versions
- Non-security crates use caret ranges (`^x.y`)
- `cargo deny check` runs in CI on every push

## Release Process

1. Update version in root `Cargo.toml` (propagates to all crates)
2. Update CHANGELOG.md with changes since last release
3. Run full CI: `cargo test`, `cargo clippy`, `cargo audit`, `cargo doc`
4. Tag release: `git tag -s v0.x.0`
5. Publish to crates.io (when ready) or distribute as source tarball

## Support Window

| Version | Support Level |
|---------|--------------|
| Latest minor (0.7.x) | Security patches + bug fixes |
| Previous minor (0.6.x) | Critical security patches only |
| Older | Unsupported |
