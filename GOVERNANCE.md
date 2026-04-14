# Governance

Craton Shield is a safety-critical embedded security runtime maintained by
**Craton Software Company**. This document describes how the project is governed,
how decisions are made, and how the community can participate.

## Governance Model

Craton Shield uses a **Benevolent Dictator** governance model during the pre-1.0
development phase. Craton Software Company holds final authority over the project
direction, releases, and security decisions. This model ensures consistency and
safety guarantees across the codebase while the project matures.

After the 1.0 release, we intend to transition to a broader governance structure
that gives long-term community contributors a formal voice in project decisions.
Details will be published in an RFC prior to the transition.

## Roles

| Role | Responsibility | Current Holders |
|:---|:---|:---|
| **Project Lead** | Final authority on direction, releases, and disputes | @craton-co/founders |
| **Core Maintainer** | Merge authority for `core/` crates, release cutting | @craton-co/core-maintainers |
| **Domain Maintainer** | Merge authority within a specific domain (`auto/`, `embedded/`, `industrial/`) | @craton-co/domain-maintainers |
| **Security Team** | Vulnerability triage, crypto review, secure boot validation | @craton-co/security-team |
| **Reviewer** | Code review, architecture feedback | Invited contributors |
| **Contributor** | Submit PRs, report issues, propose features | Anyone |

## Decision Process

### Day-to-Day Changes

Bug fixes, documentation improvements, and minor features require a single
maintainer approval to merge. All contributions go through pull requests (see
[CONTRIBUTING.md](CONTRIBUTING.md)).

### Security-Critical Changes

Changes to cryptographic primitives, key management, secure boot chains, or
any code path that affects the security guarantees of the runtime **require
review from at least one Security Team member** in addition to the relevant
domain maintainer. These PRs must include:

- A threat-model impact assessment in the PR description
- Updated tests covering the security-relevant behavior
- Explicit sign-off from a Security Team reviewer

### Minor Architectural Changes

Refactors, new internal modules, and non-breaking API additions are discussed
in the pull request itself. A single maintainer approval is sufficient.

### Major Changes (RFC Process)

The following changes require a lightweight RFC (posted as a GitHub Issue with
the `rfc` label) before implementation begins:

- New crate additions to the workspace
- Breaking API changes
- New platform or target support
- Changes to the build or release pipeline
- Dependency additions with native/C code

RFCs are open for community comment for at least 7 days. The maintainer team
makes the final decision, with reasoning documented in the issue.

## Project Domains

Craton Shield is organized into four domains, each with dedicated maintainers:

| Domain | Path | Scope |
|:---|:---|:---|
| **Core** | `core/` | Shared runtime, crypto primitives, key management, attestation |
| **Automotive** | `auto/` | Automotive security profiles, CAN/LIN bus protection, V2X |
| **Embedded** | `embedded/` | Resource-constrained targets, bare-metal support, RTOS integration |
| **Industrial** | `industrial/` | OT/ICS security, SCADA hardening, industrial protocol protection |

Cross-domain changes require approval from maintainers of all affected domains.

## Release Process

1. A maintainer creates a release branch from `main`.
2. All CI checks must pass (tests, clippy, `cargo audit`, coverage, doc build).
3. CHANGELOG.md is updated with the release date.
4. Workspace version in Cargo.toml is bumped.
5. A signed git tag is created (`v0.X.Y`).
6. The release workflow publishes crate artefacts.

## Dispute Resolution

If contributors disagree on a technical decision, discussion should continue in
the relevant PR or issue. If consensus cannot be reached, the maintainer team
makes the final call. The reasoning is documented for transparency.

## Becoming a Maintainer

Active contributors who demonstrate sustained, high-quality contributions over
at least 6 months may be invited to join the maintainer team. The existing
maintainers decide by consensus. Given the safety-critical nature of the
project, candidates must show strong understanding of embedded security
principles and Rust safety practices.

## Path to Broader Governance

After the 1.0 release, we plan to:

- Establish a Technical Steering Committee with community representation
- Formalize the RFC process with binding community votes
- Create domain-specific working groups open to external maintainers
- Publish a governance charter ratified by the community

## Code of Conduct

All participants must follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Violations are handled by the maintainer team as described in that document.
