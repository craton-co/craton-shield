# Known Limitations

**Version**: 0.7.0 | **Date**: 2026-03-28

This document lists known limitations, constraints, and areas where Craton Shield
does not provide protection. Understanding these boundaries is essential for secure
integration.

## Cryptographic Limitations

| Limitation | Impact | Mitigation |
|:---|:---|:---|
| Software crypto only (no HSM) in Core edition | Key material stored in RAM, vulnerable to cold-boot and bus-probing attacks | Use Enterprise edition with PKCS#11 HSM or TEE |
| Post-quantum crypto (`pq-software`) is development-only | ML-KEM-768 and ML-DSA-65 implementations not yet qualified for production | Do not enable `pq` feature in safety-critical paths until v1.0+ |
| `ml-dsa` crate at v0.0.4 (pre-release) | API may change in future versions | Pin dependency; monitor RustCrypto releases |
| Nonce tracking uses fixed-size ring buffer (64 entries) | Very high-frequency encryption could wrap the ring and miss reuse | Size the ring to your maximum burst rate; use monotonic counters |
| `RustCryptoProvider` is `!Sync` (uses `RefCell`) | Cannot be shared across threads via `&` reference | Use one provider per thread/core, or wrap in `Mutex` |
| Cross-reboot AES-GCM nonce reuse is not prevented by the library | Using the same key across reboots without persisted nonce state can lead to catastrophic nonce reuse (~2^32 reboots = birthday bound) | Use `NonceCounter::new_persisted()` with NVS-backed counters; rotate keys before 2^31 reboots; set `KeyManager::set_max_rotation_count()` |

## Platform Limitations

| Limitation | Impact | Mitigation |
|:---|:---|:---|
| No AUTOSAR Classic/Adaptive HAL in Core | Cannot run on AUTOSAR stacks without custom HAL | Implement `vs-hal` traits or use Enterprise QNX/AUTOSAR HAL |
| Linux HAL uses raw `libc` FFI | Not `no_std`-compatible; requires Linux/POSIX | Use only for development/testing; implement bare-metal HAL for production |
| File storage secure erase is best-effort | CoW filesystems (btrfs, ZFS) and SSDs may retain old data | Use full-disk encryption for defense-in-depth |
| Windows file permissions via `icacls` | Less granular than Unix `chmod`; requires shell execution | Use Unix/Linux for production storage |
| Stack-only allocation limits data structure sizes | Fixed capacities (e.g., 128 firewall rules, 256 CAN stats, 64 keys) | Use `capacity-large` or `capacity-xl` features for higher limits |

## Detection Limitations

| Limitation | Impact | Mitigation |
|:---|:---|:---|
| CAN allowlist uses constant-time scan for extended IDs | O(1) bitset fast-path for standard 11-bit IDs; extended 29-bit IDs fall back to O(n) constant-time scan | Standard-only allowlists get O(1) lookup automatically; mixed lists use safe fallback |
| No deep packet inspection for encrypted payloads | Cannot inspect TLS/DTLS-encrypted traffic content | Integrate with application-layer monitors |
| Anomaly detection requires tuning per vehicle | Default EWMA thresholds may not match all bus profiles | Calibrate `alpha` and `z_threshold` per vehicle model |
| No CAN-FD bit-rate switch detection | Cannot distinguish classic CAN from CAN-FD at the bit level | Relies on `is_fd` flag from HAL; validate in HAL implementation |

## Certification Limitations

| Limitation | Impact | Mitigation |
|:---|:---|:---|
| Rust compiler (rustc) not formally qualified | ISO 26262 ASIL-B requires qualified tool chain (TCL2) | Use Ferrocene qualified Rust compiler for certification |
| No formal SRS document | ISO 26262-6 requires Software Requirements Specification | SSRs documented in safety case; formal SRS planned for v1.0 |
| Code review records not yet formalized | ASIL-B requires documented review evidence | Tracked as gap in iso-26262-asil-b-assessment.md |
| FIPS 140-3 KAT vectors not implemented | `self_test()` uses structural checks, not NIST KAT | KAT implementation planned per fips-140-3-kat-plan.md |

## Out of Scope

The following are explicitly **not** protected by Craton Shield:

- **Physical attacks**: voltage glitching, electromagnetic fault injection, chip decapping
- **Supply chain attacks**: compromised toolchain, backdoored dependencies (mitigated by `cargo-audit` + `cargo-deny`)
- **Compromised HAL**: if the HAL implementation is malicious, all bets are off
- **Application-layer logic bugs**: Craton Shield monitors buses and validates updates but does not verify application correctness
- **Denial of service via hardware**: physical bus disconnection, RF jamming
- **Side-channel attacks on hardware**: power analysis, electromagnetic emanation (mitigated in Enterprise HSM edition)
