# Migration Guide: 0.6.x to 0.7.0

> This guide covers changes and migration steps when upgrading from Craton Shield 0.6.x to 0.7.0.

## Breaking Changes

### No Breaking API Changes

The 0.7.0 release introduces no breaking changes to existing core crates. All public APIs in `core/` remain backward-compatible. Existing code that compiled against 0.6.x will compile against 0.7.0 without modification.

### MSRV Unchanged

The minimum supported Rust version remains **1.82**.

## What's New in 0.7.0

### Multi-Domain Workspace Expansion

The workspace has expanded from a single `core/` directory to four domain directories:

| Directory       | Purpose                          | New Crates |
| --------------- | -------------------------------- | ---------- |
| `core/`         | Shared security primitives       | 1 (`report-iec62304`) |
| `auto/`         | Automotive security              | 7 crates   |
| `embedded/`     | Embedded IoT security            | 8 crates   |
| `industrial/`   | Industrial control system (ICS)  | 11 crates  |

The workspace now contains 49 crates total (23 core + 26 domain-specific).

### New Domain-Specific Types Crates

Each domain has a dedicated types crate that defines domain-specific packet formats, protocol envelopes, and error types:

- **`vs-types-auto`** (`auto/types-auto`) -- Automotive types: AUTOSAR frames, V2X messages, diagnostic sessions
- **`vs-types-embedded`** (`embedded/types-embedded`) -- IoT types: MQTT packets, CoAP messages, BLE PDUs, Zigbee frames, LoRa payloads
- **`vs-types-ind`** (`industrial/types-ind`) -- Industrial types: Modbus ADUs, OPC UA messages, PROFINET frames, EtherNet/IP packets

All domain types crates are `no_std` and zero-allocation.

### New Domain Runtime Orchestrators

Each domain has a runtime crate that wires together the domain's monitors and the shared core engine:

- **`vs-runtime-auto`** (`auto/runtime-auto`) -- Orchestrates AUTOSAR, V2X, signal IDS, and diagnostic gateway monitors
- **`vs-runtime-embedded`** (`embedded/runtime-embedded`) -- Orchestrates MQTT, CoAP, BLE, Zigbee, LoRa, and Modbus monitors
- **`vs-runtime-ind`** (`industrial/runtime-ind`) -- Orchestrates Modbus, OPC UA, PROFINET, EtherNet/IP, DNP3, BACnet, S7comm, IEC 60870, and IEC 61850 monitors

### New Protocol Monitors

#### Automotive (`auto/`)

| Crate              | Protocol / Function                |
| ------------------ | ---------------------------------- |
| `vs-autosar`       | AUTOSAR Classic/Adaptive monitor   |
| `vs-v2x`           | V2X (C-V2X / DSRC) monitor        |
| `vs-signal-ids`    | In-vehicle signal anomaly IDS      |
| `vs-diag-gateway`  | UDS/OBD-II diagnostic gateway      |
| `vs-ffi-auto`      | C FFI bindings for automotive      |

#### Embedded IoT (`embedded/`)

| Crate                    | Protocol           |
| ------------------------ | ------------------ |
| `vs-mqtt-monitor`        | MQTT 3.1.1 / 5.0  |
| `vs-coap-monitor`        | CoAP (RFC 7252)    |
| `vs-ble-monitor`         | Bluetooth Low Energy |
| `vs-zigbee-monitor`      | Zigbee 3.0         |
| `vs-lora-monitor`        | LoRaWAN            |
| `vs-modbus-monitor-emb`  | Modbus RTU/TCP (embedded) |

#### Industrial (`industrial/`)

| Crate                    | Protocol                   |
| ------------------------ | -------------------------- |
| `vs-modbus-monitor-ind`  | Modbus RTU/TCP (industrial) |
| `vs-opcua-monitor`       | OPC UA                     |
| `vs-profinet-monitor`    | PROFINET                   |
| `vs-ethernetip-monitor`  | EtherNet/IP (CIP)         |
| `vs-dnp3-monitor`        | DNP3                       |
| `vs-bacnet-monitor`      | BACnet                     |
| `vs-s7comm-monitor`      | S7comm (Siemens S7)        |
| `vs-iec60870-monitor`    | IEC 60870-5-104            |
| `vs-iec61850-monitor`    | IEC 61850 (MMS/GOOSE)     |

### IEC 62304 Compliance Report Generator

A new `core/report-iec62304` crate generates IEC 62304 (medical device software lifecycle) compliance reports, complementing the existing ISO 21434 and IEC 62443 report generators.

### Root-Level Documentation Overhaul

The following files were added to the repository root:

- `CODE_OF_CONDUCT.md` -- Contributor Covenant code of conduct
- `SECURITY.md` -- Vulnerability reporting and disclosure policy
- `SUPPORT.md` -- Support channels and resources

### GitHub Issue and PR Templates

GitHub templates were added under `.github/`:

- Issue templates for bug reports, feature requests, and security issues
- Pull request template with checklist

## Step-by-Step Migration

1. **Update Cargo.toml dependency version**
   ```toml
   [dependencies]
   craton-shield = "0.7.0"
   ```

2. **Update workspace members (if you use a workspace)**

   If you maintain a workspace that includes Craton Shield crates as path dependencies, add the new domain directories to your workspace members. The new top-level directories are `auto/`, `embedded/`, and `industrial/`.

3. **Enable domain feature flags if needed**

   The new domain crates are optional. To use automotive, embedded, or industrial monitors, add the relevant crates to your dependencies:

   ```toml
   # Automotive
   vs-runtime-auto = { git = "https://github.com/craton-co/craton-shield", tag = "v0.7.0" }

   # Embedded IoT
   vs-runtime-embedded = { git = "https://github.com/craton-co/craton-shield", tag = "v0.7.0" }

   # Industrial
   vs-runtime-ind = { git = "https://github.com/craton-co/craton-shield", tag = "v0.7.0" }
   ```

4. **No code changes required for existing core usage**

   If you only use crates from `core/`, no source code changes are needed. All core APIs are backward-compatible.

5. **Run tests to verify**
   ```bash
   cargo test --workspace
   ```

## New Features Available After Migration

- **Multi-domain monitoring**: Deploy Craton Shield across automotive, IoT, and industrial environments using domain-specific runtime orchestrators.
- **26 new protocol monitors**: Cover MQTT, CoAP, BLE, Zigbee, LoRa, Modbus, OPC UA, PROFINET, EtherNet/IP, DNP3, BACnet, S7comm, IEC 60870, IEC 61850, AUTOSAR, V2X, signal IDS, and diagnostic gateway protocols.
- **IEC 62304 compliance reports**: Generate medical device software lifecycle compliance documentation alongside existing ISO 21434 and IEC 62443 reports.
- **Domain-specific types**: Strongly-typed, `no_std` packet definitions for each protocol domain, enabling compile-time correctness for protocol handling.
