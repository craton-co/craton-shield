# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial open-source release preparation.
- Root-level documentation: `CODE_OF_CONDUCT.md`, `SECURITY.md`, `SUPPORT.md`.
- GitHub Issue and Pull Request templates (`.github/ISSUE_TEMPLATE/`, `.github/pull_request_template.md`).
- `GOVERNANCE.md` — project governance model.
- `MAINTAINERS.md` — maintainer team and responsibilities.
- `ROADMAP.md` — community-facing development roadmap.
- `ACKNOWLEDGMENTS.md` — third-party credits and acknowledgments.
- `RELEASING.md` — release process documentation.
- Migration guide for 0.6→0.7 (`core/docs/migration-guide-0.6-to-0.7.md`).
- Developer Certificate of Origin (DCO) requirement in `CONTRIBUTING.md`.

### Fixed
- Version references updated from 0.6.0 to 0.7.0 in `safety-manual.md`, `porting-guide.md`, `threat-model.md`, and `performance-results.md`.
- Email domain inconsistency: unified all contact addresses to `craton.com.ar` across documentation (`SECURITY.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `MAINTAINERS.md`, `safety-manual.md`, `.github/FUNDING.yml`, `.github/ISSUE_TEMPLATE/security.md`).
- Broken cross-repository links: replaced external `craton-shield-auto` repo references with local `auto/` directory paths across all documentation.
- Broken relative link in `auto/autosar/README.md` (now points to `core/docs/architecture.md`).
- Architecture document clarified as describing core layer within the 47-crate multi-domain workspace.
- Root README documentation section expanded with links to deployment guide, safety manual, known limitations, migration guides, and roadmap.

## [0.7.0] - 2026-04-13

### Added

**Runtime and architecture**
- 47-crate workspace spanning four security domains: Core (21 crates),
  Automotive (7), Embedded IoT (8), Industrial OT/ICS (11).
- `#![no_std]` throughout; zero heap allocation; ~280 KiB flash footprint.
- Workspace-wide `#![forbid(unsafe_code)]`; unsafe confined to `vs-ffi` (6
  blocks) and `vs-hal-linux` (29 blocks, hardware I/O only).
- `CratonShield` orchestrator with per-subsystem health tracking
  (`Ready / Degraded / Failed / NotInitialized`), configurable watchdog, and
  monotonic tick loop.
- Domain runtimes: `AutomotiveShield`, `EmbeddedShield`, `IndustrialShield`.

**Cryptography (`vs-crypto`)**
- `RustCryptoProvider`: AES-256-GCM, SHA-256, HMAC-SHA-256, ECDSA P-256,
  ECDH P-256 via RustCrypto; RFC 6979 deterministic signing.
- `RustCryptoPqProvider`: ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204).
- Power-on and periodic self-tests with NIST KAT vectors (SHA-256 FIPS 180-4,
  AES-256-GCM NIST SP 800-38D, HMAC RFC 4231, ECDSA RFC 6979, ECDH NIST CAVP).
- Compile-time `compile_error!` guards prevent mock / PQ-software providers
  from being included in `release` builds.
- `NonceTracker` with Bloom-filter-backed reuse detection; cumulative nonce
  counter persists across key rotations to prevent AES-GCM birthday attacks.

**Key management (`vs-key-manager`)**
- 64 key slots; algorithms: AES-128-GCM, AES-256-GCM, HMAC-SHA-256,
  ECDSA P-256, ECDH P-256.
- Purpose binding (Bus Auth, Firmware Verification, Diagnostic Session,
  Telemetry Encryption, OTA Update) prevents cross-purpose key misuse.
- Zeroize-on-drop for all key material via the `zeroize` crate.
- 256-entry HMAC-chained audit ring with overflow callback and `fail_closed`
  mode (rejects new operations when the ring would overflow without a callback).
- Configurable maximum key lifetime and maximum rotation count.

**Network monitoring**
- `vs-can-monitor`: 5-detector pipeline (ID allowlist / rate limiting / DLC /
  entropy / replay) at ~265 ns per frame; 1,024-entry stats map; SipHash-2-4
  replay tracker with CLOCK-style eviction when full.
- `vs-eth-monitor`: ARP spoofing, DHCP starvation, SOME/IP service-discovery
  anomalies, DoIP session tracking, IPv6 extension-header abuse, at ~28 ns.
- `vs-netfw`: L2–L4 firewall with 128-rule default capacity (256 / 512 via
  features), priority ordering, token-bucket rate limiting, default-deny.
- `vs-ids-engine`: cross-protocol alert correlation with configurable time
  window and severity escalation.
- `vs-anomaly`: EWMA inter-arrival time scoring for CAN and Ethernet.

**Security services**
- `vs-secure-boot`: ECDSA P-256 boot-chain attestation, PCR management,
  `SoftwareTpm` reference implementation.
- `vs-ota-validator`: TUF 4-role delegation (Root / Timestamp / Snapshot /
  Targets), P-256 threshold signing, rollback protection via monotonic counter.
- `vs-integrity`: SHA-256 memory-region integrity with HMAC-authenticated
  baseline updates and constant-time comparison.
- `vs-event-logger`: HMAC-SHA-256 chained tamper-evident audit log (256 / 512 /
  1,024 entries via features); monotonic sequence numbers.
- `vs-policy-engine`: XACML-lite engine with 64 rules, time-bounded validity,
  and three combining algorithms (FirstApplicable, DenyOverrides,
  PermitOverrides); default-deny.

**Domain extensions**
- Automotive: AUTOSAR SecOC scaffolding, V2X IEEE 1609.2 validator, UDS
  diagnostic gateway with brute-force lockout.
- Embedded IoT: MQTT, CoAP, BLE, Zigbee, LoRa, Modbus monitors.
- Industrial OT/ICS: Modbus, OPC UA, PROFINET, EtherNet/IP, DNP3, BACnet,
  S7comm, IEC 60870-5-104, IEC 61850 monitors; IEC 62443 zone/conduit support.

**C FFI (`vs-ffi`)**
- Full C ABI with `catch_unwind` at every boundary; `DEGRADED` state machine
  blocks operations after panic/mutex-poison recovery; runtime `catch_unwind`
  functional check at init.
- Error codes mapped from `VsError`; compile-time ABI size assertions.
- `cbindgen`-generated `cratonshield.h`.

**Testing and quality**
- 26 integration test suites (3,200+ tests): attack scenarios, crypto KAT
  vectors, fault injection, key lifecycle, OTA attack simulation, PQ
  integration, property-based (proptest), WCET stats, zeroization.
- 9 cargo-fuzz targets: CAN frames, Ethernet packets, OTA JSON, policy engine,
  firewall, integrity, nonce counter, AES-GCM, IP/TCP parsing.

**Compliance documentation**
- `core/docs/threat-model.md`: STRIDE analysis with mitigations.
- `core/docs/safety-manual.md`: ASIL-B integration assumptions.
- Certification templates: ISO 26262 ASIL-B gap analysis, ISO/SAE 21434 gap
  analysis, FIPS 140-3 security policy and KAT plan, IEC 62443 SL-2 evidence,
  penetration test plan, UN R155/R156 evidence.
- Compliance report generators for ISO 21434, IEC 62443, and IEC 62304.

**Developer experience**
- `ARCHITECTURE.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`, `RELEASING.md`.
- Migration guides: 0.5→0.6 and 0.6→0.7.
- Performance results, hardware compatibility, porting guide, deployment
  guides for automotive, embedded, and industrial domains.
- `cargo deny` configuration, Dependabot for Cargo and GitHub Actions.

[Unreleased]: https://github.com/craton-co/craton-shield/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/craton-co/craton-shield/releases/tag/v0.7.0
