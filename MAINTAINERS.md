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
  [SECURITY.md](SECURITY.md). Security patches follow the SLA documented in
  `SECURITY.md`; maintainers commit to participate in that timeline.
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

## v1.0 Release Sign-off

> Applies to the v1.0.0 release and every subsequent **minor** release on the
> 1.x line. Patch releases follow the lighter-weight workflow in
> [`RELEASING.md`](RELEASING.md). The branching contract is in
> [`BRANCHING.md`](BRANCHING.md); the security SLA in
> [`SECURITY.md`](SECURITY.md); the performance budget in
> [`PERFORMANCE.md`](PERFORMANCE.md).

The 1.0 release marks the start of API/ABI stability commitments. To make
those commitments real, every minor release on the 1.x line ships only after
explicit sign-off from a reviewer in each domain table below. A single
maintainer cannot sign off in two domains for the same release.

### Required sign-off matrix

| Domain      | Surface covered by sign-off                                                                                                          | Required reviewer (team or named maintainer)                       |
|-------------|--------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------|
| **Core**    | `core/` crates: runtime, crypto, key-manager, secure-boot, netfw, policy-engine, event-logger, IDS engine, anomaly, integrity, types | [@craton-co/core-maintainers](https://github.com/orgs/craton-co/teams/core-maintainers) |
| **Auto**    | `auto/` crates: AUTOSAR, V2X, signal-ids, diag-gateway, runtime-auto, types-auto, ffi-auto                                           | [@craton-co/auto-maintainers](https://github.com/orgs/craton-co/teams/auto-maintainers) |
| **Embedded**| `embedded/` crates: MQTT, CoAP, BLE, Zigbee, LoRa, Modbus-emb, runtime-embedded, types-embedded                                      | [@craton-co/embedded-maintainers](https://github.com/orgs/craton-co/teams/embedded-maintainers) |
| **Industrial** | `industrial/` crates: Modbus-ind, OPC UA, PROFINET, EtherNet/IP, DNP3, BACnet, S7comm, IEC 60870, IEC 61850, runtime-ind, types-ind | [@craton-co/industrial-maintainers](https://github.com/orgs/craton-co/teams/industrial-maintainers) |
| **FFI**     | `core/ffi`, `auto/ffi-auto`, generated `core/include/*.h`, `cbindgen.toml`, ABI changes affecting external C consumers               | [@craton-co/core-maintainers](https://github.com/orgs/craton-co/teams/core-maintainers) **and** [@craton-co/security-team](https://github.com/orgs/craton-co/teams/security-team) (joint sign-off; counts as one slot) |
| **Security**| Crypto correctness, FIPS 140-3 KAT regressions, secure-boot chain, vulnerability triage, `cargo audit` / `cargo deny` posture        | [@craton-co/security-team](https://github.com/orgs/craton-co/teams/security-team) |

The **Project Lead** ([@craton-co/founders](https://github.com/orgs/craton-co/teams/founders))
provides the final go-ahead after the per-domain reviewers have approved.
This is a ceremonial step that confirms the matrix is satisfied; it does
not substitute for the domain reviews.

### What each reviewer attests to

By signing off on a 1.x release, the domain reviewer attests that, for the
crates in their domain:

1. **No undocumented breaking change.** Every change since the previous
   minor that affects the public API surface is either:
   (a) explicitly listed in `CHANGELOG.md` under `Changed` / `Removed` /
       `Deprecated` with a migration note, or
   (b) gated behind a feature flag that is off by default.
2. **No unreviewed `unsafe` block.** The workspace-wide
   `unsafe_code = "deny"` lint is intact; exceptions in the FFI boundary
   have been re-reviewed since the last release.
3. **All domain tests pass** on the GitHub Actions matrix used by the
   release branch, including the no_std `thumbv7em-none-eabihf` check
   where applicable.
4. **Performance posture is acceptable.** No operation in
   [`PERFORMANCE.md`](PERFORMANCE.md) belonging to the domain has regressed
   beyond its CI budget without a written justification in the release
   notes.
5. **Security advisories are current.** No open GHSA against the domain is
   shipping in an exploitable state; any open advisory is either fixed in
   this release or has a documented mitigation in `core/docs/`.

The Security Team additionally attests, for the release as a whole, that:

- `cargo audit` reports no actionable advisories.
- `cargo deny check` passes against the published `deny.toml`.
- FIPS 140-3 KAT vectors (from v0.8) still pass against the shipped crypto
  primitives.
- The CVE Response SLA in [`SECURITY.md`](SECURITY.md) has been honored for
  every report in the window between this release and the previous minor.

### Sign-off mechanics

Sign-off is recorded in the release PR (`release/vX.Y.0`) as a top-level
comment from each required reviewer, using the template:

```
domain: <core|auto|embedded|industrial|ffi|security>
release: vX.Y.0
attest: <yes|no>
notes: <optional, but required if any check above is "with caveats">
```

The release PR cannot be merged until every required `attest: yes` line is
present and dated within the 14 days preceding the merge. A `no` blocks the
release until resolved -- escalate via the path in the "Escalation Path"
section above.

### Sign-off for patch releases

Patch releases on a `release/1.x` branch require **two** sign-offs:

- The domain reviewer for whichever domain the fix lands in (Core if the
  fix is cross-domain).
- The Security Team if the patch addresses a CVE-tracked issue or touches
  any of: `core/crypto`, `core/key-manager`, `core/secure-boot`,
  `core/integrity`.

The full sign-off matrix is not required for patches; the lighter rule
reflects that patch releases are bug-fix-only per
[`BRANCHING.md`](BRANCHING.md).
