# Architecture Overview

This document provides a high-level map of the Craton Shield workspace. For the
full architecture document with formal diagrams, dependency graphs, and safety
analysis, see [`core/docs/architecture.md`](core/docs/architecture.md).

---

## Workspace Layout

```
craton-shield/
├── core/               Core security primitives (23 crates)
│   ├── types/          Shared types, errors, constants
│   ├── hal/            Hardware abstraction traits
│   ├── hal-linux/      Linux HAL (SocketCAN, raw Ethernet)
│   ├── crypto/         Cryptographic provider traits + implementations
│   ├── can-monitor/    CAN bus intrusion detection
│   ├── eth-monitor/    Ethernet IDS (SOME/IP, DoIP, ARP)
│   ├── ids-engine/     Alert correlation engine
│   ├── anomaly/        EWMA-based anomaly detection
│   ├── integrity/      Memory region integrity monitoring
│   ├── netfw/          Network firewall (L2-L4)
│   ├── policy-engine/  XACML-lite policy evaluation
│   ├── event-logger/   HMAC-chained tamper-evident logging
│   ├── evidence-envelope/  Structured metadata envelope for compliance/audit reports
│   ├── health/         Per-subsystem health state machine with deterministic auto-recovery
│   ├── key-manager/    Key lifecycle management
│   ├── ota-validator/  TUF/Uptane OTA validation
│   ├── secure-boot/    Boot chain verification + PCR
│   ├── storage/        Persistent storage abstraction
│   ├── ffi/            C FFI bindings
│   ├── runtime/        Main platform orchestrator
│   ├── report-*/       Compliance report generators
│   ├── docs/           Architecture, safety, certification docs
│   ├── examples/       Runnable Rust and C examples
│   ├── benches/        Criterion benchmarks
│   ├── fuzz/           Fuzz targets
│   └── tests/          Integration tests
├── auto/               Automotive domain (7 crates)
│   ├── types-auto/     Automotive types (extends vs-types)
│   ├── autosar/        AUTOSAR Classic/Adaptive integration
│   ├── v2x/            V2X (IEEE 1609.2) validation
│   ├── signal-ids/     CAN signal-level anomaly detection
│   ├── diag-gateway/   UDS diagnostic gateway
│   ├── runtime-auto/   Automotive runtime orchestrator
│   └── ffi-auto/       Automotive C FFI bindings
├── embedded/           Embedded IoT domain (8 crates)
│   ├── types-embedded/ Embedded IoT types (extends vs-types)
│   ├── mqtt-monitor/   MQTT protocol monitor
│   ├── coap-monitor/   CoAP protocol monitor
│   ├── ble-monitor/    BLE protocol monitor
│   ├── zigbee-monitor/ Zigbee/IEEE 802.15.4 monitor
│   ├── lora-monitor/   LoRaWAN monitor
│   ├── modbus-monitor-emb/ Modbus monitor (IoT variant)
│   └── runtime-embedded/   Embedded runtime orchestrator
├── industrial/         Industrial OT/ICS domain (11 crates)
│   ├── types-ind/      Industrial types (extends vs-types)
│   ├── modbus-monitor-ind/ Modbus monitor (ICS variant)
│   ├── opcua-monitor/  OPC UA monitor
│   ├── profinet-monitor/   PROFINET IO monitor
│   ├── ethernetip-monitor/ EtherNet/IP monitor
│   ├── dnp3-monitor/   DNP3 monitor
│   ├── bacnet-monitor/ BACnet monitor
│   ├── s7comm-monitor/ S7comm monitor
│   ├── iec60870-monitor/   IEC 60870-5-104 monitor
│   ├── iec61850-monitor/   IEC 61850 MMS/GOOSE monitor
│   └── runtime-ind/    Industrial runtime orchestrator
└── .github/            CI workflows, issue/PR templates
```

---

## Layered Dependency Model

Dependencies flow strictly downward. No lateral or upward dependencies.

```
Layer 3  INTEGRATION     vs-runtime, vs-ids-engine, vs-ffi
                         vs-runtime-auto, vs-runtime-embedded, vs-runtime-ind
Layer 2  SUBSYSTEMS      vs-crypto, vs-netfw, vs-policy-engine, vs-anomaly,
                         vs-can-monitor, vs-eth-monitor, vs-event-logger,
                         vs-integrity, vs-key-manager, vs-ota-validator,
                         vs-secure-boot, vs-storage
                         + domain monitors (vs-mqtt-monitor, vs-opcua-monitor, ...)
Layer 1  HAL             vs-hal (traits), vs-hal-linux (Linux impl)
Layer 0  TYPES           vs-types, vs-types-auto, vs-types-embedded, vs-types-ind
```

---

## Domain Relationship

Each domain layer **extends** the core stack:

- **Core** provides protocol-agnostic security primitives (crypto, firewall, policy, IDS correlation, logging, key management).
- **Domain crates** add protocol-specific monitors and a domain runtime that composes core subsystems with domain monitors.
- **Domain type crates** (`vs-types-auto`, `vs-types-embedded`, `vs-types-ind`) extend `vs-types` and re-export all core types. Domain crates depend on their domain types crate rather than `vs-types` directly.

```
vs-runtime-auto ──────► vs-runtime (core)
    │                       │
    ├── vs-signal-ids       ├── vs-can-monitor
    ├── vs-v2x              ├── vs-eth-monitor
    ├── vs-diag-gateway     ├── vs-netfw
    └── vs-autosar          └── vs-ids-engine
            │                       │
            v                       v
      vs-types-auto ──────► vs-types (core)
```

---

## Naming Convention

- **Cargo package names** use a `vs-` prefix: `vs-crypto`, `vs-can-monitor`, `vs-runtime-auto`
- **Directory names** use bare names: `core/crypto`, `core/can-monitor`, `auto/runtime-auto`
- Use the `vs-` prefixed name with Cargo commands (`cargo test -p vs-crypto`)
- Use the directory path for file system operations

---

## Design Principles

| Principle | Enforcement |
|:----------|:------------|
| No heap allocation | `#![no_std]`, fixed-capacity arrays, stack-only |
| No `unsafe` code | `unsafe_code = "deny"` workspace-wide (except `core/ffi/`) |
| No `std` | All crates compile for `thumbv7em-none-eabihf` (CI-verified) |
| Default-deny | Firewall, policy engine, diagnostic gateway |
| Constant-time comparison | `subtle::ConstantTimeEq` for all security checks |
| HMAC-chained logging | Tamper-evident audit trail via `vs-event-logger` |
| Deterministic execution | Bounded loops, no recursion, WCET-analyzed hot paths |

---

## Further Reading

- [Full Architecture Document](core/docs/architecture.md) — formal layered architecture with diagrams
- [Threat Model](core/docs/threat-model.md) — STRIDE analysis, trust boundaries
- [Safety Manual](core/docs/safety-manual.md) — ASIL-B integration assumptions
- [Performance Results](core/docs/performance-results.md) — WCET benchmarks, binary sizes
- [Hardware Compatibility](core/docs/hardware-compatibility.md) — supported platforms
