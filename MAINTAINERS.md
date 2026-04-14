# Maintainers

This file lists the current maintainers of Craton Shield and their areas of
responsibility. Craton Shield is maintained by **Craton Software Company**.

## Active Maintainers

### Project Lead

| Name | GitHub | Area |
|:---|:---|:---|
| Craton Founders | [@craton-co/founders](https://github.com/orgs/craton-co/teams/founders) | Overall direction, final authority |

### Core Maintainers

Responsible for the `core/` crates: shared runtime, crypto primitives, key
management, and attestation.

| Name | GitHub | Area |
|:---|:---|:---|
| Core Team | [@craton-co/core-maintainers](https://github.com/orgs/craton-co/teams/core-maintainers) | `core/` crates |

### Domain Maintainers

Responsible for domain-specific crates and platform integrations.

| Name | GitHub | Area |
|:---|:---|:---|
| Auto Team | [@craton-co/auto-maintainers](https://github.com/orgs/craton-co/teams/auto-maintainers) | `auto/` -- Automotive security |
| Embedded Team | [@craton-co/embedded-maintainers](https://github.com/orgs/craton-co/teams/embedded-maintainers) | `embedded/` -- Embedded targets |
| Industrial Team | [@craton-co/industrial-maintainers](https://github.com/orgs/craton-co/teams/industrial-maintainers) | `industrial/` -- OT/ICS security |

### Security Team

Responsible for cryptographic correctness, key management, secure boot chains,
and vulnerability response.

| Name | GitHub | Area |
|:---|:---|:---|
| Security Team | [@craton-co/security-team](https://github.com/orgs/craton-co/teams/security-team) | Crypto, key management, secure boot, vulnerability triage |

## Responsibilities

- **Code review**: All PRs require at least one maintainer approval before merge.
  Security-critical changes additionally require Security Team sign-off.
- **Release management**: Cutting releases, updating CHANGELOG.md, tagging
  versions, and publishing crate artefacts.
- **Security response**: Triaging and resolving vulnerability reports per
  [SECURITY.md](SECURITY.md). Target response within 48 hours; patches within
  72 hours for critical issues.
- **Architecture decisions**: Approving new crates, breaking changes, and
  dependency additions via the RFC process described in
  [GOVERNANCE.md](GOVERNANCE.md).
- **Community health**: Responding to issues, reviewing community PRs, mentoring
  contributors, and enforcing the [Code of Conduct](CODE_OF_CONDUCT.md).

## Escalation Path

1. **Domain question or PR review**: Tag the relevant domain maintainer team.
2. **Cross-domain or architectural decision**: Tag @craton-co/core-maintainers.
3. **Security vulnerability**: Email [security@craton.com.ar](mailto:security@craton.com.ar).
   Do **not** open a public issue. See [SECURITY.md](SECURITY.md) for the full
   disclosure process.
4. **Governance or dispute resolution**: Tag @craton-co/founders.

## Contact

- **General questions**: Open a [GitHub Issue](https://github.com/craton-co/craton-shield/issues)
- **Security vulnerabilities**: [security@craton.com.ar](mailto:security@craton.com.ar) (see [SECURITY.md](SECURITY.md))
- **Commercial licensing**: [license@craton.com.ar](mailto:license@craton.com.ar)
- **Enterprise edition**: See [craton-shield-enterprise](https://github.com/craton-co/craton-shield-enterprise)

## Becoming a Maintainer

Active contributors who demonstrate sustained, high-quality contributions over
at least 6 months may be invited to join the maintainer team. Candidates should
show strong understanding of embedded security principles and Rust safety
practices. See [GOVERNANCE.md](GOVERNANCE.md) for details.

### Individual Contributor Transparency

The maintainer slots above are currently listed as GitHub team handles because
Craton Shield is at an early stage of community growth. As the project matures,
individual contributors who reach maintainer status should be listed by name to
provide accountability and allow the community to direct thanks, questions, and
mentorship requests to specific people.

**Guidelines for listing individual maintainers:**

- A contributor who has been invited as a maintainer after meeting the 6-month
  criteria above should be added to the relevant table as a named row alongside
  or instead of the team handle, in the format:

  ```
  | First Last | [@github-handle](https://github.com/github-handle) | Area description |
  ```

- Individual entries take precedence over team entries for routing review
  requests; list the most relevant individual first.
- When a named maintainer becomes inactive (no review, commit, or issue
  response for 90 days) they should be moved to an **Emeritus** subsection
  below the active table rather than deleted, preserving attribution.
- External contributors are encouraged to self-nominate by opening an issue
  tagged `maintainership`; the founding team will respond within 30 days.

This policy ensures that community members know who to work with, and that
individuals receive appropriate credit for their long-term contributions to a
safety-critical project.

## Bus Factor Mitigation

- All maintainers have full repository access.
- CI/CD secrets are stored in GitHub organization-level secrets, accessible to
  all maintainers.
- Release signing keys are held by at least two maintainers.
- The project is licensed under Apache-2.0, ensuring it remains freely available
  regardless of maintainer availability.
