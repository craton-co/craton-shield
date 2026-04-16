# Getting Support

Thank you for using Craton Shield! If you need help, please follow these guidelines to get the best support experience.

## Search Existing Resources

Before asking a question, please check if your issue has already been addressed:

- **Documentation**: Read the [root README](README.md) and the [detailed documentation in `core/docs/`](core/docs/).
- **Inner READMEs**: Each crate has its own `README.md` with specific details.
- **GitHub Issues**: Search through [open and closed issues](https://github.com/craton-co/craton-shield/issues).

## Where to Ask

### GitHub Issues

For bug reports and feature requests, please use [GitHub Issues](https://github.com/craton-co/craton-shield/issues). Make sure to use the provided templates.

### Community Discussions

For general questions, architecture discussions, or sharing your projects, please use [GitHub Discussions](https://github.com/craton-co/craton-shield/discussions).

## Professional Services

For enterprise-grade support, custom integrations, or certification assistance (ISO 26262, IEC 62443), please contact Craton Software Company via our [Enterprise Edition](https://github.com/craton-co/craton-shield-enterprise) page.

## Reporting Bugs

When reporting a bug, please include:

- A clear description of the problem.
- Your environment (Rust version, target hardware, OS if applicable).
- Steps to reproduce the issue.
- Expected vs. actual behavior.
- Relevant log output or error messages.

## Security Issues

**Do not report security issues via GitHub Issues.** Please follow our [Security Policy](SECURITY.md).

## Supported Release Lines

> Effective from v1.0.0. The 0.x line follows the looser pre-1.0 policy
> documented in [`core/docs/api-stability.md`](core/docs/api-stability.md).
> The branching model that backs this support matrix is in
> [`BRANCHING.md`](BRANCHING.md).

At any given time, **two `1.x` release lines** are actively supported:

| Tier                | What you get                                                                       | Backported fixes                                  |
|---------------------|------------------------------------------------------------------------------------|---------------------------------------------------|
| **Current minor**   | All bug fixes, all security fixes, dependency updates, docs, performance patches   | Every fix that lands on `main` and qualifies      |
| **Previous minor**  | Bug fixes that are Critical or High severity, all security fixes (per SLA), docs   | Critical/High bugs and all CVE-tracked security fixes |
| **Older minors**    | EOL -- no fixes shipped, no SLA                                                    | Best-effort only, on commercial agreement         |

A "minor line" is the set of `1.Y.Z` releases sharing the same `Y`. The
backport rules in [`BRANCHING.md`](BRANCHING.md) determine what is eligible
to land on the line's `release/1.Y` branch.

### EOL timeline

When a new minor `1.Y.0` ships:

1. `1.Y.0` becomes the **current minor**.
2. `1.(Y-1).x` (whatever was previously current) becomes the **previous
   minor**.
3. `1.(Y-2).x` (whatever was previously the previous minor) becomes **EOL**
   and its `release/1.(Y-2)` branch is frozen. The branch is preserved for
   audit purposes; no new commits land there.

EOL is announced **on the day of the minor release** in the release notes,
in [`CHANGELOG.md`](CHANGELOG.md) under the `Removed` section, and emailed
to known commercial integrators. There is no separate deprecation period for
a minor line -- the deprecation happens at the moment the third-newest minor
becomes the second-newest minor.

Exceptions:

- **Critical security issues** are backported to **every** non-EOL line, full
  stop. Commercial integrators on an EOL line may request a one-off backport
  through the enterprise channel; pricing and timeline are case-by-case.
- **A `1.x.0` line** that has been designated long-term-support (LTS) in its
  release notes is supported for the duration stated in those notes,
  overriding the rolling two-line rule. As of v1.0.0, no line carries the
  LTS designation; see [`BRANCHING.md`](BRANCHING.md) for the open question.

### Supported versions (live)

| Version line | Status            | Latest patch | EOL date          |
|--------------|-------------------|--------------|-------------------|
| 1.0.x        | Current minor     | TBD          | When 1.2.0 ships  |
| 0.7.x        | Pre-1.0, frozen   | 0.7.0        | When 1.0.0 ships  |
| < 0.7        | EOL               | n/a          | EOL               |

This table is updated on every minor release as part of the
[`RELEASING.md`](RELEASING.md) checklist.

### Recommended-upgrade matrix

If you are pinned to an older version, the table below summarises the
shortest defensible upgrade path. "Defensible" means the path that minimises
behavioural surprises and traverses every published migration guide.

| From          | To (recommended)    | Path                                                                                          | Migration guides to read                                                          |
|---------------|---------------------|-----------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------|
| 0.5.x         | 1.0.x               | 0.5.x -> 0.6.x -> 0.7.x -> 1.0.x                                                              | `migration-guide-0.5-to-0.6.md`, `migration-guide-0.6-to-0.7.md`, 0.7 -> 1.0 (TBD) |
| 0.6.x         | 1.0.x               | 0.6.x -> 0.7.x -> 1.0.x                                                                       | `migration-guide-0.6-to-0.7.md`, 0.7 -> 1.0 (TBD)                                  |
| 0.7.x         | 1.0.x               | 0.7.x -> 1.0.x (direct)                                                                       | 0.7 -> 1.0 (TBD, ships with the 1.0.0 release)                                    |
| 1.0.x         | latest 1.0.x        | Patch upgrade                                                                                  | None -- patch releases are drop-in within a minor line                            |
| 1.0.x         | latest 1.1.x (future) | Minor upgrade (when 1.1 ships)                                                              | 1.0 -> 1.1 migration guide (will ship with 1.1.0)                                 |

We do **not** recommend skipping minor lines on the 1.x family even though
SemVer permits it -- migration guides are authored against the
immediate-predecessor's behaviour, and skipping one means combining two sets
of behavioural deltas in your head.

### What "supported" entitles you to

For the open-source Apache-2.0 distribution, "supported" means:

- The right to file issues against the version and have them triaged.
- The right to security fixes per [`SECURITY.md`](SECURITY.md)'s CVE Response
  SLA.
- Backported bug fixes per the table above.

"Supported" does **not** entitle you to:

- A timeline guarantee on non-security bug fixes.
- Custom backports of features.
- Direct access to maintainers.

For SLA-backed support, custom backports, or extended LTS, contact
`license@craton.com.ar` for the enterprise edition.
