# Changelog

All notable changes to `vs-secure-boot` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to Semantic Versioning.

## [0.7.0]

### Breaking

- **`BootEntry` signature wire format bumped from v1 to v2.** The
  signed pre-image now includes the `BootStage` discriminant
  (4-byte little-endian `u32`) alongside the image hash, preventing
  cross-stage signature substitution attacks. Signatures produced
  under v1 (image hash only) will **not** verify under v2 and vice
  versa.

### Migration

Re-sign every boot image with `BootEntry::sign` (or directly via
`BootEntry::compute_signing_digest` + `CryptoProvider::sign_p256`)
before upgrading deployed verifiers. The new constant
`BOOT_ENTRY_SIGNATURE_VERSION = 2` documents the active wire format.

### Security

- `BootVerifier::verify_boot_chain` now rejects chains that skip
  stages (e.g. `[Bootloader, Application(0)]` omitting `Hypervisor`
  and `Os`) with `VsError::PolicyViolation`.
- `BootVerifier::replace_pub_key_authorized` rejects
  self-authorization (a slot signing its own rotation).
- `SoftwareTpm`/`HardwareTpm` `quote` rejects an empty PCR selection.
