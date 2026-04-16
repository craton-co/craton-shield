# Release Process

This document describes how to cut a new release of Craton Shield.

## Prerequisites

- Write access to the `main` branch
- Member of `@craton-co/founders`
- GPG key configured for tag signing
- All CI checks passing on `main`

## Pre-Release Checklist

Before starting the release process, verify the following:

- [ ] All CI workflows are green on `main`
- [ ] `CHANGELOG.md` has been updated (items moved from `[Unreleased]`)
- [ ] Version bumped in root `Cargo.toml`
- [ ] Documentation version references are up to date
- [ ] `cargo audit` reports no actionable advisories
- [ ] `cargo deny check` passes
- [ ] No unresolved security advisories (see `SECURITY.md`)

## Version Bump Process

Craton Shield uses a single workspace version defined in the root `Cargo.toml`. Updating the version there propagates it to all workspace crates (currently 49 crates across `core/`, `auto/`, `embedded/`, and `industrial/`).

```toml
[workspace.package]
version = "X.Y.Z"
```

No per-crate version bumps are needed. All crates share the workspace version via `version.workspace = true` in their individual `Cargo.toml` files.

## Steps

### 1. Prepare the release

```bash
# Ensure you're on an up-to-date main
git checkout main && git pull

# Create a release branch
git checkout -b release/vX.Y.Z
```

### 2. Update version numbers

Update the version in the root `Cargo.toml`:

```toml
[workspace.package]
version = "X.Y.Z"
```

### 3. Update CHANGELOG.md

Follow the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format:

- Move items from `[Unreleased]` to a new `[X.Y.Z] - YYYY-MM-DD` section
- Organize entries under `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`
- Add a migration guide under `core/docs/` if there are breaking changes
- Update the comparison links at the bottom of the file

### 4. Update SECURITY.md

- Update the supported versions table to reflect the new release

### 5. Verify CI passes

Run the full verification suite locally:

```bash
cargo fmt --all -- --check
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo deny check
cargo audit
cargo doc --workspace --no-deps
```

### 6. Commit and create PR

```bash
git add -A
git commit -m "release: prepare vX.Y.Z"
git push -u origin release/vX.Y.Z
gh pr create --title "release: vX.Y.Z" --body "Release preparation for vX.Y.Z"
```

### 7. Merge and tag

After PR approval and CI pass:

```bash
# Merge the PR (squash)
gh pr merge --squash

# Tag the release (GPG-signed)
git checkout main && git pull
git tag -s vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

All release tags **must** be GPG-signed (`git tag -s`). Unsigned tags will be rejected by branch protection rules.

### 8. Create GitHub Release

```bash
gh release create vX.Y.Z --title "vX.Y.Z" --notes-file - <<EOF
See [CHANGELOG.md](CHANGELOG.md#xyz--yyyy-mm-dd) for full details.
EOF
```

## Post-Release

1. **Announce the release** on the project's communication channels.
2. **Monitor for regressions** -- watch CI on `main` and issue tracker for the first 48 hours.
3. **Update downstream** -- notify the sibling repos (`craton-shield-avia`, `craton-shield-med`, `craton-shield-enterprise`) if they need to bump their dependency.

## Versioning Policy

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html):

- **Major** (X): Breaking changes to public API or behavior
- **Minor** (Y): New features, non-breaking additions
- **Patch** (Z): Bug fixes, security patches, documentation

## Hotfix Process

For critical security fixes that cannot wait for a regular release:

1. Branch from the latest release tag: `git checkout -b hotfix/vX.Y.Z+1 vX.Y.Z`
2. Apply the fix with a minimal, focused changeset
3. Update `CHANGELOG.md` with a `Security` entry
4. Follow steps 5-8 above (verify, commit, merge, tag)
5. Cherry-pick the fix to `main` if applicable

For vulnerability-driven releases, follow the coordinated disclosure process described in [SECURITY.md](SECURITY.md).

## crates.io Publication

All 49 workspace crates are published to crates.io. Because the workspace is a
single connected dependency graph, publication must proceed in dependency
order: a crate cannot reference a version of an internal dependency that
crates.io has not yet indexed. The tiers below reflect that order; within a
tier, ordering does not matter.

### Prerequisites

- [ ] `CARGO_REGISTRY_TOKEN` configured locally (`cargo login`) and scoped to a
      crates.io account with publish rights on every `vs-*` crate.
- [ ] Working tree is clean (`git status` reports nothing to commit) and the
      checkout is on the signed release tag (`git describe --exact-match`).
- [ ] Tag exists and is GPG-signed (e.g. `v0.7.1`), per the steps above.
- [ ] `CHANGELOG.md` entry for the release is finalized and merged.
- [ ] Full verification suite is green: `cargo build --workspace`,
      `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`.
- [ ] `cargo deny check` is clean.
- [ ] `cargo doc --workspace --no-deps` builds without warnings.

### Step 1 -- Dry-run validation

For each crate, run:

```bash
cargo publish --dry-run -p <crate>
```

`--dry-run` validates packaging, manifest metadata, license file inclusion, and
README rendering, but it **cannot** resolve a `version = "X.Y.Z"` dependency on
an internal crate until that crate is real-published to crates.io. For the
first publish of a tier, expect dry-runs of dependents to fail with "no
matching package found"; dry-run each tier *after* the previous tier has been
real-published in Step 2.

### Step 2 -- Publish in dependency order

Run `cargo publish -p <crate>` for each crate, tier by tier. Wait for index
propagation (Step 3) between tiers before publishing the next one.

- **Tier 0 -- Types / no internal deps**
  - `vs-types`
  - `vs-types-auto`
  - `vs-types-embedded`
  - `vs-types-ind`

- **Tier 1 -- Depends on types only**
  - `vs-health`
  - `vs-anomaly`
  - `vs-evidence-envelope`
  - `vs-hal`

- **Tier 2 -- Crypto and storage stack**
  - `vs-crypto` (publish first within the tier)
  - `vs-key-manager`
  - `vs-secure-boot`
  - `vs-storage`
  - `vs-event-logger`
  - `vs-integrity`
  - `vs-ota-validator`

- **Tier 3 -- Policy and core monitors**
  - `vs-policy-engine`
  - `vs-netfw`
  - `vs-can-monitor`
  - `vs-eth-monitor`
  - `vs-ids-engine`

- **Tier 4 -- Monitor crates (order within tier does not matter)**
  - Embedded: `vs-mqtt-monitor`, `vs-coap-monitor`, `vs-ble-monitor`,
    `vs-zigbee-monitor`, `vs-lora-monitor`, `vs-modbus-monitor-emb`
  - Industrial: `vs-modbus-monitor-ind`, `vs-opcua-monitor`,
    `vs-profinet-monitor`, `vs-ethernetip-monitor`, `vs-dnp3-monitor`,
    `vs-bacnet-monitor`, `vs-s7comm-monitor`, `vs-iec60870-monitor`,
    `vs-iec61850-monitor`
  - Auto: `vs-signal-ids`

- **Tier 5 -- HAL implementation and report generators**
  - `vs-hal-linux`
  - `vs-report-iec62443`
  - `vs-report-iso21434`
  - `vs-report-iec62304`

- **Tier 6 -- Auto domain feature crates**
  - `vs-autosar`
  - `vs-v2x`
  - `vs-diag-gateway`

- **Tier 7 -- Runtimes**
  - `vs-runtime`
  - `vs-runtime-auto`
  - `vs-runtime-embedded`
  - `vs-runtime-ind`

- **Tier 8 -- FFI shims (publish last)**
  - `vs-ffi`
  - `vs-ffi-auto`

### Step 3 -- Wait for index propagation

After publishing each tier, wait **30-60 seconds** before publishing the next
tier so the crates.io sparse index can serve the new versions. The next tier's
`cargo publish` will fail with "no matching package found" if the index has
not yet caught up; if that happens, sleep and retry rather than republishing.

### Step 4 -- Verification

For every published crate:

1. Visit `https://crates.io/crates/<crate>` and confirm the new version is
   listed, the README renders, and the listed features match the manifest.
2. Visit `https://docs.rs/<crate>/<version>` and confirm the build succeeded.
   The `[package.metadata.docs.rs]` section in each crate's `Cargo.toml`
   controls the rendered docs configuration; if a build fails on docs.rs,
   inspect the build log there before publishing a follow-up patch.
3. Confirm `cargo add <crate>@<version>` resolves in a scratch project.

### Step 5 -- Rollback note

**crates.io publishes are immutable.** A published `X.Y.Z` cannot be edited,
overwritten, or deleted. The only available recourse is `cargo yank`, which
marks the version as un-selectable by *new* `Cargo.toml` resolutions; existing
`Cargo.lock` files continue to resolve against the yanked version.

```bash
# Yank a specific crate-version pair
cargo yank --vers X.Y.Z <crate>

# Un-yank (only if the yank itself was a mistake -- see Yank Policy below)
cargo yank --vers X.Y.Z --undo <crate>
```

A workspace-wide release rollback is one `cargo yank` invocation per affected
crate. See the **Yank Policy** section below for when yanking is the right
call versus publishing a patch release.

Until you have published a release, you can also depend on Craton Shield via
git as a fallback:

```toml
[dependencies]
vs-types = { git = "https://github.com/craton-co/craton-shield", tag = "v0.7.0" }
```

## Yank Policy

> Effective from v1.0.0. The policy applies to every Craton Shield crate
> published to crates.io.

`cargo yank` is a downgrade-only signal: yanking a version does not delete it
from the registry, but new `Cargo.toml` resolutions skip it. Existing
`Cargo.lock` files still resolve. This makes yank the right tool when a
published version must not be picked up by new consumers, but **not** a way
to "delete" a release.

### When to yank

Yank a published version if **any** of the following is true:

1. **Confirmed Critical vulnerability** (CVSS >= 9.0) with a plausible
   exploitation path against the default configuration. See the "CVE Response
   SLA" section of [SECURITY.md](SECURITY.md) for the procedure -- yank is
   immediate, before the patched release is cut.
2. **The release is fundamentally broken**: it fails to build, fails its own
   tests, or panics on the documented entry-point inputs. Yank, then publish
   `X.Y.Z+1` with the fix.
3. **An incorrect security output**: a verifier returns "valid" for invalid
   input, a constant-time check has a data-dependent branch, the firewall's
   default-deny path is reachable as default-allow. These are correctness
   regressions in the security promise itself; yank regardless of severity
   classification.
4. **A licensing or attribution mistake** that needs to be removed from the
   chain of downstream copies (e.g. a vendored dependency under an
   incompatible license slipped in). Yank, then publish `X.Y.Z+1` with the
   offending content removed.

### When to deprecate (not yank)

Deprecate -- by publishing a new minor with `#[deprecated]` on the offending
items and a migration note in `core/docs/` -- if **all** of the following are
true:

- The existing version is **safe to use** as documented.
- A better API exists or is on the way.
- Continuing to consume the deprecated version is a maintenance choice, not
  a security or correctness exposure.

Deprecation gives integrators time to migrate without breaking their pinned
builds. Use deprecation for: replaced APIs, configuration flags that no longer
make sense, modules that have moved between crates.

### When to publish a patch (not yank, not deprecate)

Publish `X.Y.Z+1` and **leave `X.Y.Z` un-yanked** if the bug:

- Has a low CVSS score (< 7.0) and no immediate exploitability concern.
- Affects an edge case that integrators are unlikely to hit by default.
- Is fixed in the new release such that the upgrade path is a no-op (no
  config changes, no API changes).

This is the common case for routine bug-fix releases. Yanking would impose
churn on existing users for no proportionate benefit.

### Yank execution checklist

When yanking is the right call:

1. **Identify the full version set.** A single vulnerability can affect a
   range; yank every crate-version pair in the range, not just the latest.
   For workspace-wide releases, that is one yank command per crate per
   version:

   ```bash
   for crate in vs-types vs-crypto vs-runtime ...; do
       cargo yank --vers X.Y.Z "$crate"
   done
   ```

2. **Record the yank** in the GHSA, in `CHANGELOG.md` under a `Security`
   subsection of the *next* release, and in `core/docs/known-limitations.md`
   if the issue has a published workaround. The CHANGELOG entry must list:
   - the crate-version pairs yanked,
   - the date and time (UTC),
   - the GHSA identifier and CVE,
   - the version integrators should move to.

3. **Notify downstream.** Open issues on the sibling repos
   (`craton-shield-avia`, `craton-shield-med`, `craton-shield-enterprise`) and
   email known commercial integrators per the disclosure list.

4. **Do not un-yank.** A patched release supersedes the yanked one; we do not
   reverse a yank after the fact. If a yank turns out to be unjustified
   (false-positive report, mis-classified severity), publish a corrective
   GHSA explaining the situation and let the regular `>= X.Y.Z+1`
   constraint move integrators forward.

5. **Audit afterwards.** Within 30 days of the yank, file the post-mortem
   referenced in [SECURITY.md](SECURITY.md) under
   `core/docs/security-postmortems/`. Include whether yanking was the right
   tool and what would change the decision next time.
