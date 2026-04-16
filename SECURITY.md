# Security Policy

## Supported Versions

We provide security updates for the current major version. Older versions may be supported on a case-by-case basis.

| Version | Supported          |
| ------- | ------------------ |
| 0.7.x   | :white_check_mark: |
| < 0.7.0 | :x:                |

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

We take the security of Craton Shield seriously. If you believe you've found a security vulnerability, please report it to us by emailing [security@craton.com.ar](mailto:security@craton.com.ar).

### What to include

To help us triage and resolve the issue quickly, please include:

- A descriptive title for the vulnerability.
- A summary of the vulnerability.
- Step-by-step instructions to reproduce the issue.
- Impact description (if known).
- Affected crates and versions.

### Our Process

1. We will acknowledge receipt of your report within **48 hours**.
2. We will investigate the issue and determine its severity.
3. We will provide a timeline for resolution and keep you updated.
4. Once resolved, we will credit you for the discovery (unless you prefer to remain anonymous).

## Responsible Disclosure

We follow a **90-day coordinated disclosure** policy:

- We will work to deliver a fix within **30 days** for critical vulnerabilities
  and within **90 days** for all others.
- If we cannot fix the issue within 90 days, we will notify you and agree on
  a short extension.
- After the fix is shipped (or 90 days from the report date, whichever comes
  first), you are free to publish your findings. We will simultaneously publish
  a GitHub Security Advisory.
- We ask that you do not publicly disclose details of the vulnerability before
  the coordinated date, except to organisations that need to know for their own
  defence (e.g., affected downstream integrators).

We appreciate your help in keeping Craton Shield secure.

## Encrypted Reporting

For sensitive vulnerability details, you may encrypt your report using our
PGP public key. The current key is published at:

- <https://craton.com.ar/.well-known/security.pgp>
- Also available on request from [security@craton.com.ar](mailto:security@craton.com.ar)

Before trusting the key, please verify the fingerprint out-of-band by
contacting any of the maintainers listed in [MAINTAINERS.md](MAINTAINERS.md).

If you do not have PGP set up, plaintext email to
[security@craton.com.ar](mailto:security@craton.com.ar) is also acceptable -- we will
follow up over an encrypted channel if the report contains sensitive details.

## CVE Assignment

For confirmed vulnerabilities, Craton Software Company will:

1. Request a CVE ID through the appropriate CNA.
2. Publish a GitHub Security Advisory (GHSA) with the CVE details.
3. Include the fix in a patch release with the CVE referenced in the [CHANGELOG](CHANGELOG.md).
4. Credit the reporter in both the advisory and changelog (unless anonymity is requested).

## CVE Response SLA

> Applies to every non-EOL release line listed in [SUPPORT.md](SUPPORT.md),
> with the following two-tier commitment:
>
> - **0.7.x (pre-1.0):** the SLA below is **best-effort**. The same workflow,
>   severity tiers, and target timelines apply, but they are not yet binding
>   guarantees because the project has not committed to long-term support
>   windows for pre-1.0 releases.
> - **1.0.0 and later:** the SLA below is **binding** for every non-EOL
>   release line.
>
> The 90-day disclosure cap, acknowledgement commitment, and embargo period
> apply uniformly to both tiers.

### Maximum disclosure window: 90 days

From the date a valid report reaches `security@craton.com.ar` to the
public-disclosure date is **at most 90 calendar days**, regardless of severity.
This is a hard cap, not a target. If we cannot fix the issue within 90 days
we may negotiate a short extension with the reporter; if no agreement is
reached, the reporter is free to disclose at the 90-day mark and we publish
the advisory in parallel.

### Severity-driven internal targets

We use the [CVSS v3.1 base score](https://www.first.org/cvss/v3-1/specification-document)
to classify severity. The targets below are internal commitments for the time
between **report acknowledgement** and **patch availability** (the public
disclosure window above is unchanged).

| Severity                  | CVSS score | Target patch availability | Required release line(s) patched |
|---------------------------|------------|---------------------------|-----------------------------------|
| Critical                  | 9.0 - 10.0 | **7 days**                | Every non-EOL 1.x line + immediate `cargo yank` of vulnerable versions |
| High                      | 7.0 - 8.9  | 30 days                   | Latest minor + previous minor     |
| Medium                    | 4.0 - 6.9  | 60 days                   | Latest minor                      |
| Low                       | 0.1 - 3.9  | Next scheduled patch (no SLA) | Latest minor (best-effort)    |
| Informational / hardening | n/a        | Next minor                 | `main` only                       |

### Immediate `cargo yank` on confirmed Critical vulnerabilities

For any vulnerability that triages to **Critical** (CVSS >= 9.0) **and** has a
plausible exploitation path against a default deployment:

1. The security team yanks every affected published version on crates.io
   immediately upon confirmation, *before* the patched release is cut.
   - `cargo yank --vers <X.Y.Z> <crate>` is run for every affected crate-version
     pair across the workspace.
   - Yanking is a downgrade-only signal: existing `Cargo.lock` files continue
     to resolve, but new dependents cannot pick up a vulnerable version.
2. The reporter, the GHSA, and `CHANGELOG.md` all note the yank with a date
   and the list of affected versions.
3. A patched release follows under the 7-day Critical target. If 7 days
   passes with no patch, the security team posts an interim mitigation
   (configuration workaround, feature-flag disablement) on the GHSA.
4. Yanked versions are **not** un-yanked once a fix lands; consumers move
   forward to the patched version. The yank policy in [RELEASING.md](RELEASING.md)
   covers when to yank vs deprecate vs publish a patch.

For High-severity issues, yanking is at the security team's discretion based
on exploitability; for Medium and below, yanking is reserved for cases where
the affected version contains a regression that produces incorrect security
output (e.g. a verifier that returns "valid" for invalid input).

### GHSA workflow

Every confirmed vulnerability is shepherded through the
[GitHub Security Advisory (GHSA)](https://docs.github.com/en/code-security/security-advisories)
process. The lifecycle:

1. **Draft created** within 48 hours of report acknowledgement. The reporter
   is invited as a collaborator on the draft GHSA where they can review the
   write-up before publication.
2. **CVE requested** through GitHub's CNA delegation as soon as severity is
   confirmed and the affected version range is finalized.
3. **Private fork (temporary)** is opened against the affected
   `release/1.x` branch(es); the patch is developed and reviewed in the
   private fork to avoid early disclosure through public PR diffs.
4. **Coordinated release**: GHSA published, patch released, `cargo yank`
   executed (if applicable), and `CHANGELOG.md`'s `Security` section updated
   in a single coordinated window. The window is announced to known
   integrators with at least 24 hours' notice via the security mailing list.
5. **Post-incident**: a short post-mortem is filed under
   `core/docs/security-postmortems/<CVE-id>.md` within 30 days of the public
   disclosure, covering root cause, detection latency, and any process
   improvements. Post-mortems for Critical issues are public; for High and
   below they may be redacted at the maintainers' discretion.

### What counts as "report receipt" for SLA timers

The clock starts when a maintainer with security access reads the report. To
avoid disputes:

- Reports to `security@craton.com.ar` are auto-acknowledged within 1 hour
  with a timestamped reference number.
- The 48-hour acknowledgement commitment, the severity-target clock, and the
  90-day disclosure cap all key off that timestamp.
- If a report sits in the queue for more than 48 hours without human
  acknowledgement, the on-call security maintainer is paged.
