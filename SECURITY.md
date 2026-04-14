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
