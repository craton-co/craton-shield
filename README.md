# Craton Shield

**Embedded intrusion detection and prevention runtime for safety-critical systems.**

[![CI](https://github.com/craton-co/craton-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/craton-co/craton-shield/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.82-blue.svg)](https://blog.rust-lang.org/)

`#![no_std]` | zero-heap | ~280 KiB flash | 3,200+ tests | 122K lines of Rust

Craton Shield is a modular, multi-domain cybersecurity runtime for resource-constrained embedded devices. It provides real-time intrusion detection, network firewalling, cryptographic integrity, secure boot, and OTA validation -- all without dynamic memory allocation.

## Domains

| Domain | Layer | Crates | Protocols |
|:---|:---|---:|:---|
| **Core** | Shared security primitives | 21 | CAN, Ethernet, SOME/IP |
| **Automotive** | Vehicle-specific IDS | 7 | AUTOSAR, V2X, UDS, Signal IDS |
| **Embedded IoT** | Constrained device monitoring | 8 | MQTT, CoAP, BLE, Zigbee, LoRa, Modbus |
| **Industrial** | OT/ICS protocol monitoring | 11 | Modbus, OPC UA, PROFINET, EtherNet/IP, DNP3, BACnet, S7comm, IEC 60870, IEC 61850 |

## Architecture

```
Layer 3  INTEGRATION     vs-runtime, vs-ids-engine, vs-ffi
Layer 2  SUBSYSTEMS      vs-crypto, vs-netfw, vs-policy-engine, vs-anomaly, ...
Layer 1  HAL             vs-hal (traits), vs-hal-linux (Linux impl)
Layer 0  TYPES           vs-types (shared enums, structs, errors)
```

Dependencies flow strictly downward. Domain layers (auto, embedded, industrial) extend the core stack with protocol-specific monitors and runtimes.

Full architecture documentation: [`core/docs/architecture.md`](core/docs/architecture.md)

## Performance

All operations fit within a 10 us CAN gateway budget (x86_64, `release` profile):

| Operation | Latency |
|:---|---:|
| CAN frame (5 detectors) | ~265 ns |
| Ethernet inspection | ~28 ns |
| Firewall (128 rules) | ~166 ns |
| Policy engine (64 rules) | ~199 ns |
| Runtime tick (idle) | ~73 ns |
| AES-128-GCM (256 B) | ~907 ns |

See [`core/docs/performance-results.md`](core/docs/performance-results.md) for full benchmarks.

## Quick Start

```bash
# Requirements: Rust 1.82+
rustup update stable

# Build the entire workspace
cargo build --workspace

# Run all tests
cargo test --workspace

# Check no_std compatibility (Cortex-M)
rustup target add thumbv7em-none-eabihf
cargo check --target thumbv7em-none-eabihf -p vs-types -p vs-crypto -p vs-runtime

# Run local CI (mirrors GitHub Actions)
./scripts/local-ci.sh --fast

# Or run inside a Linux container that mirrors the GitHub Actions runner
./scripts/local-ci-docker.sh --fast
```

## Workspace

<details>
<summary>47 crates across 4 domains</summary>

### Core (21 crates)

| Crate | Description |
|:---|:---|
| `vs-types` | Shared types, error enums, constants |
| `vs-crypto` | AES-256-GCM, SHA-256, HMAC, ECDSA P-256, ECDH |
| `vs-key-manager` | Key storage, rotation, and lifecycle |
| `vs-secure-boot` | Boot chain attestation with TPM support |
| `vs-can-monitor` | CAN bus IDS (flood, DLC, fuzzing, replay) |
| `vs-eth-monitor` | Ethernet IDS (ARP/DHCP anomaly, SOME/IP) |
| `vs-ids-engine` | CAN/Ethernet correlation engine |
| `vs-anomaly` | EWMA-based anomaly scoring |
| `vs-integrity` | Constant-time integrity verification |
| `vs-netfw` | Network firewall (128 rules, L3/L4) |
| `vs-ota-validator` | TUF/Uptane OTA metadata validation |
| `vs-event-logger` | HMAC-chained tamper-evident audit log |
| `vs-policy-engine` | Hierarchical rule evaluation engine |
| `vs-storage` | Persistent storage abstraction |
| `vs-runtime` | Main orchestrator / tick loop |
| `vs-ffi` | C FFI bindings (cbindgen) |
| `vs-hal` | Hardware abstraction traits |
| `vs-hal-linux` | Linux HAL (SocketCAN, raw Ethernet) |
| `vs-report-iec62443` | IEC 62443 compliance report generator |
| `vs-report-iso21434` | ISO/SAE 21434 compliance report generator |
| `vs-report-iec62304` | IEC 62304 compliance report generator |

### Automotive (7 crates)

| Crate | Description |
|:---|:---|
| `vs-types-auto` | Automotive-specific types |
| `vs-autosar` | AUTOSAR Adaptive integration |
| `vs-v2x` | V2X message validation |
| `vs-signal-ids` | Signal-level anomaly detection |
| `vs-diag-gateway` | UDS diagnostic gateway (0x27 SecurityAccess) |
| `vs-runtime-auto` | Automotive runtime orchestrator |
| `vs-ffi-auto` | Automotive C FFI bindings |

### Embedded IoT (8 crates)

| Crate | Description |
|:---|:---|
| `vs-types-embedded` | Embedded IoT types |
| `vs-mqtt-monitor` | MQTT protocol monitor |
| `vs-coap-monitor` | CoAP protocol monitor |
| `vs-ble-monitor` | BLE protocol monitor |
| `vs-zigbee-monitor` | Zigbee protocol monitor |
| `vs-lora-monitor` | LoRa protocol monitor |
| `vs-modbus-monitor-emb` | Modbus monitor (embedded) |
| `vs-runtime-embedded` | Embedded runtime orchestrator |

### Industrial (11 crates)

| Crate | Description |
|:---|:---|
| `vs-types-ind` | Industrial types |
| `vs-modbus-monitor-ind` | Modbus TCP/RTU monitor |
| `vs-opcua-monitor` | OPC UA protocol monitor |
| `vs-profinet-monitor` | PROFINET protocol monitor |
| `vs-ethernetip-monitor` | EtherNet/IP protocol monitor |
| `vs-dnp3-monitor` | DNP3 protocol monitor |
| `vs-bacnet-monitor` | BACnet protocol monitor |
| `vs-s7comm-monitor` | S7comm protocol monitor |
| `vs-iec60870-monitor` | IEC 60870-5-104 protocol monitor |
| `vs-iec61850-monitor` | IEC 61850 MMS/GOOSE monitor |
| `vs-runtime-ind` | Industrial runtime orchestrator |

</details>

## Standards Alignment

| Standard | Domain | Status |
|:---|:---|:---|
| **ISO/SAE 21434** | Automotive cybersecurity | Designed to support |
| **UN R155** | Vehicle type approval | Technical controls implemented |
| **ISO 26262 ASIL-B** | Functional safety | Targeting (not certified) |
| **AUTOSAR AP R22-11** | Automotive software | ARXML manifest provided |
| **IEC 62443** | Industrial cybersecurity | Report generator included |
| **IEC 62304** | Medical device software | Report generator included |

## Design Principles

- **No heap allocation** -- all data structures are stack-allocated with fixed capacities
- **No `unsafe` code** -- `unsafe_code = "deny"` enforced workspace-wide (except FFI boundary)
- **No `std`** -- every crate compiles for `thumbv7em-none-eabihf` (Cortex-M4F)
- **Default-deny** -- firewall, policy engine, and diagnostic gateway deny by default
- **Constant-time comparison** -- integrity checks use `subtle::ConstantTimeEq`
- **HMAC-chained logging** -- tamper-evident audit trail with cryptographic chain

## Documentation

### Getting Started

- [Installation Guide](INSTALL.md)
- [Architecture Overview](ARCHITECTURE.md)
- [Core Architecture (detailed)](core/docs/architecture.md)
- [Deployment Guide](core/docs/deployment.md)
- [Porting Guide](core/docs/porting-guide.md)
- [Hardware Compatibility](core/docs/hardware-compatibility.md)

### Domain Guides

- [Automotive Deployment](auto/docs/deployment-guide.md)
- [Embedded IoT Deployment](embedded/docs/deployment-guide.md)
- [Industrial OT/ICS Deployment](industrial/docs/deployment-guide.md)

### Reference

- [Feature Flags](core/docs/feature-flags.md)
- [API Stability](core/docs/api-stability.md)
- [Safety Manual](core/docs/safety-manual.md)
- [Threat Model](core/docs/threat-model.md)
- [Known Limitations](core/docs/known-limitations.md)
- [Performance Results](core/docs/performance-results.md)
- [Integration Examples](core/docs/integration-examples.md)
- [Migration Guide (0.5→0.6)](core/docs/migration-guide-0.5-to-0.6.md)
- [Migration Guide (0.6→0.7)](core/docs/migration-guide-0.6-to-0.7.md)
- [FAQ](core/docs/faq.md)

### Project

- [Roadmap](ROADMAP.md)
- [Changelog](CHANGELOG.md)
- [Security Policy](SECURITY.md)
- [Support Guide](SUPPORT.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

## Enterprise Edition

[Craton Shield Enterprise](https://github.com/craton-co/craton-shield-enterprise) adds hardware-backed cryptography (PKCS#11, TPM 2.0), QNX RTOS support, and fleet telemetry under a Business Source License.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and pull request guidelines. All contributions require a [Developer Certificate of Origin](https://developercertificate.org/) sign-off (`git commit -s`).

See also: [Governance](GOVERNANCE.md) | [Maintainers](MAINTAINERS.md) | [Acknowledgments](ACKNOWLEDGMENTS.md) | [Installation](INSTALL.md) | [Architecture](ARCHITECTURE.md)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

```
Copyright 2026 Craton Software Company
SPDX-License-Identifier: Apache-2.0
```
