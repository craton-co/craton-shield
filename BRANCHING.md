# Branching and Release Policy

> **Status:** Effective from v1.0.0.
> **Scope:** All crates in the Craton Shield workspace (Apache-2.0). The
> enterprise edition tracks this policy but ships under its own cadence.

Craton Shield targets safety-critical embedded use. Long-lived integrations
on real ECUs need predictable update paths and clear answers to "what will
break when I take this patch?". This document is that contract.

## Versioning

Craton Shield follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

- **Major (`X.0.0`)** -- Breaking change to a public Rust API, the C FFI ABI,
  the on-disk event-log format, or any documented behavioural guarantee
  (default-deny, constant-time integrity check, panic-safe FFI boundary).
- **Minor (`X.Y.0`)** -- New crates, new features behind a feature flag, new
  defaulted public APIs, performance improvements that change measured
  latency.
- **Patch (`X.Y.Z`)** -- Bug fixes, security patches, documentation, dependency
  bumps that do not change behaviour, internal refactors.

The MSRV (currently 1.82) is treated as part of the public API: bumping it
requires a minor release at minimum.

## Branch model

```
main ───────────────●─●─●─●─●─●─●─●─●─●──────────►   (next minor, 1.y+1.0)
                    │             │
                    │             └─ release/1.y.0
                    │
release/1.x ──●─●─●─●─────────────────►              (1.x bug-fix line)
              │ │ │
              │ │ └─ v1.x.2
              │ └─── v1.x.1
              └───── v1.x.0
```

- **`main`** is always shippable as the *next* minor or major. Day-to-day
  development lands here.
- **`release/1.x`** is a long-lived branch that hosts the patch series for an
  `1.x` line. Branches are created at the time of the `1.x.0` tag and
  destroyed (or moved to "frozen") when the line reaches EOL per
  [`SUPPORT.md`](SUPPORT.md).
- **`release/vX.Y.Z`** (short-lived, lower-case) are the per-release
  preparation branches described in [`RELEASING.md`](RELEASING.md). They are
  squash-merged into the appropriate long-lived branch.

## What lands where

| Branch                | Accepts                                                                 | Does not accept                                  |
|-----------------------|-------------------------------------------------------------------------|--------------------------------------------------|
| `main`                | Features, breaking changes, refactors, fixes, docs, dependency bumps    | Nothing -- this is the firehose                  |
| `release/1.x`         | **Bug fixes only.** Security patches. Documentation. Dependency security bumps. | Features. API additions. Behaviour changes. Performance "improvements" that change measured latency. MSRV bumps. |
| `release/2.x` (future)| Same rules as `release/1.x`, scoped to the 2.x line                     | Same exclusions                                  |

Anything that would require a minor version bump under SemVer is not eligible
for backport to a `release/1.x` branch -- it belongs on `main` and ships in
the next minor.

## Backport process

1. Land the fix on `main` first. This anchors the change in the line that gets
   the broadest test coverage.
2. Cherry-pick to the relevant `release/1.x` branch with `git cherry-pick -x`
   (the `-x` annotates the new commit with the original SHA so the audit trail
   is preserved). If the cherry-pick produces a non-trivial conflict, open a
   separate PR against `release/1.x` with the adapted patch rather than
   silently rewriting the fix.
3. Open a PR titled `backport(1.x): <original title>`. Reference the original
   PR in the description.
4. Backport PRs require the same review level as the original (security fixes
   need security-team sign-off on both branches).
5. Tag and release per [`RELEASING.md`](RELEASING.md).

## Cadence

| Release type | Typical cadence       | Triggered by                                                      |
|--------------|-----------------------|-------------------------------------------------------------------|
| Patch (1.x.Z) | As needed, no SLA except security (see [`SECURITY.md`](SECURITY.md)) | Bug fix, security advisory, broken dependency |
| Minor (1.y.0) | ~Quarterly             | Accumulated features on `main` reach a coherent milestone        |
| Major (2.0.0) | When required, with at least one minor of advance notice on `main` | Breaking change that cannot be deferred behind a feature flag |

There is **no** scheduled major-release calendar. We avoid major bumps; when
one is unavoidable, we publish a migration guide in `core/docs/` and run a
deprecation cycle on `main` for at least one full minor release before the
major lands.

## Branch protection

The following rules are enforced on every release branch:

- `main` -- linear history, signed commits, all required checks green,
  at least one maintainer approval.
- `release/1.x` -- linear history, signed commits, all required checks green,
  **two** approvals (one of which must be on the security team for any change
  that touches `core/crypto`, `core/key-manager`, `core/secure-boot`, or
  `core/integrity`).
- Force pushes are disabled on all `release/*` branches without exception.
- Tags `v1.*` are protected and must be GPG-signed by a release maintainer.

## Long-term support summary

- **Two concurrent `1.x` lines** are supported at any time: the latest minor
  (full support) and the prior minor (bug-fix and security only). When a new
  minor ships, the oldest of the previously-supported lines moves to EOL.
- Critical-severity security fixes are backported to **every** non-EOL line.
- High-severity security fixes are backported to the latest minor only,
  unless an active integrator requests otherwise.
- See [`SUPPORT.md`](SUPPORT.md) for the live EOL schedule and the
  recommended-upgrade matrix.

## Pre-1.0 carve-out

This policy takes effect at v1.0.0. The 0.x line follows the looser pre-1.0
semantics described in [`core/docs/api-stability.md`](core/docs/api-stability.md):
breaking changes are allowed in minor versions, and there are no long-lived
release branches.

## Open questions deferred to v2.0

These are intentionally out of scope until 2.0 planning begins:

- Whether to introduce LTS designation on a *specific* 1.x line (e.g. mark
  1.3.x as a 3-year LTS to align with an automotive program).
- Whether to publish `release/1.x` ABI shims so a C FFI consumer can mix
  Craton Shield versions across modules.
