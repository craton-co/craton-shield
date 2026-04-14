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

Craton Shield uses a single workspace version defined in the root `Cargo.toml`. Updating the version there propagates it to all workspace crates (currently 47 crates across `core/`, `auto/`, `embedded/`, and `industrial/`).

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

Publication to crates.io is planned for the 1.0 release. Until then, depend on Craton Shield via git:

```toml
[dependencies]
vs-types = { git = "https://github.com/craton-co/craton-shield", tag = "v0.7.0" }
```
