# Industrial OT/ICS Deployment Guide

> Craton Shield Industrial 0.7.0

This guide covers deployment of the Craton Shield industrial runtime
(`vs-runtime-ind`) in OT/ICS environments — SCADA systems, DCS networks,
PLC gateways, and substation automation. For core deployment concepts, see the
[Core Deployment Guide](../../core/docs/deployment.md).

---

## Target Environments

| Environment | Typical Hardware | Protocols | Standards |
|:------------|:-----------------|:----------|:----------|
| SCADA gateway | x86/ARM Linux | Modbus TCP, DNP3, OPC UA | IEC 62443, NERC CIP |
| DCS controller | Cortex-A / x86 | Modbus, EtherNet/IP, PROFINET | IEC 62443 |
| Substation IED | Cortex-M7 / ARM | IEC 61850, IEC 60870 | IEC 62443, IEC 62351 |
| PLC security proxy | Cortex-M4F | Modbus RTU/TCP, S7comm | IEC 62443 |
| Building automation | Cortex-M4F | BACnet, Modbus | IEC 62443 |

---

## IEC 62443 Zone/Conduit Model

The industrial runtime implements IEC 62443 zone and conduit security levels.
Zones group assets by security requirements; conduits are the communication
paths between zones.

```rust
use vs_types_ind::{Zone, Conduit, SecurityLevel};

let zone_control = Zone {
    id: 1,
    name: "Process Control",
    security_level: SecurityLevel::Sl3,
};

let zone_enterprise = Zone {
    id: 2,
    name: "Enterprise Network",
    security_level: SecurityLevel::Sl1,
};

let conduit = Conduit {
    id: 1,
    source_zone: 1,
    dest_zone: 2,
    security_level: SecurityLevel::Sl2,  // Enforced at conduit boundary
};
```

---

## Protocol Monitors

### Stack Budgets

| Monitor | Stack | Detection Capabilities |
|:--------|------:|:-----------------------|
| `vs-modbus-monitor-ind` | ~350 B | Unit ID filtering, function code enforcement, register ranges, rate limiting |
| `vs-opcua-monitor` | ~2.0 KB | Security mode enforcement, session tracking, replay detection, endpoint allowlist |
| `vs-profinet-monitor` | ~1.5 KB | Frame ID filtering, DCP blocking, cycle counter validation, alarm flood detection |
| `vs-ethernetip-monitor` | ~700 B | Session tracking, command allowlist, rate limiting |
| `vs-dnp3-monitor` | ~500 B | Function code allowlist, address validation, write protection |
| `vs-bacnet-monitor` | ~300 B | Service choice allowlist, write/dangerous operation protection |
| `vs-s7comm-monitor` | ~500 B | PDU-type allowlist, function code filtering, SZL filtering |
| `vs-iec60870-monitor` | ~500 B | TypeID allowlist, COT filtering, I-frame sequence tracking |
| `vs-iec61850-monitor` | ~600 B | MMS service-type allowlist, GOOSE replay detection, test-flag blocking |
| `vs-runtime-ind` | ~10 KB | Composes all monitors + zone/conduit management |

Total stack for full deployment: **~17 KB** (all monitors + runtime).

---

## Build Configuration

```bash
# Linux SCADA gateway (full)
cargo build --release -p vs-runtime-ind

# Cortex-M bare-metal (substation IED)
cargo build --release --target thumbv7em-none-eabihf -p vs-runtime-ind

# Single protocol monitor
cargo build --release -p vs-opcua-monitor
```

### Capacity Tiers

| Resource | Base | Large | XL |
|:---------|-----:|------:|---:|
| Modbus unit rules | 32 | 64 | 128 |
| OPC UA sessions | 16 | 32 | 64 |
| PROFINET devices | 32 | 64 | 128 |
| Zone definitions | 16 | 32 | 64 |
| Conduit definitions | 32 | 64 | 128 |
| Recent alerts buffer | 64 | 128 | 256 |

---

## Initialization

```rust
use vs_runtime_ind::{IndustrialShield, IndustrialConfig};
use vs_crypto::SoftwareCryptoProvider;

let config = IndustrialConfig::default();
let crypto = SoftwareCryptoProvider::default();
let mut shield = IndustrialShield::init(config, crypto)?;

// Configure zones and conduits
shield.add_zone(zone_control)?;
shield.add_zone(zone_enterprise)?;
shield.add_conduit(conduit)?;
```

---

## Protocol-Specific Configuration

### Modbus (SCADA)

```rust
use vs_modbus_monitor::{ModbusMonitor, UnitAction, FunctionPolicy};

let mut monitor = shield.modbus_monitor_mut();
monitor.add_rule(
    1,                         // Unit ID
    UnitAction::Allow,
    FunctionPolicy::ReadOnly,  // Only reads permitted
    0, 999,                    // Register range
    50,                        // Rate limit (req/sec)
)?;
```

### OPC UA

```rust
use vs_opcua_monitor::{OpcUaConfig, SecurityMode};

let config = OpcUaConfig {
    required_security_mode: SecurityMode::SignAndEncrypt,
    max_sessions: 16,
    ..Default::default()
};
```

### PROFINET

```rust
use vs_profinet_monitor::ProfinetConfig;

let config = ProfinetConfig {
    block_dcp: true,           // Block DCP discovery (common attack vector)
    strict_mode: true,         // Reject unknown frame IDs
    ..Default::default()
};
```

---

## Network Architecture Patterns

### Recommended: Defense-in-Depth

```
┌──────────────────────────────────────────────────┐
│  Enterprise Network (SL-1)                       │
└──────────┬───────────────────────────────────────┘
           │ Conduit (SL-2, vs-netfw firewall)
┌──────────▼───────────────────────────────────────┐
│  DMZ / Historian (SL-2)                          │
│  vs-opcua-monitor (read-only enforcement)        │
└──────────┬───────────────────────────────────────┘
           │ Conduit (SL-3, vs-netfw firewall)
┌──────────▼───────────────────────────────────────┐
│  Process Control (SL-3)                          │
│  vs-modbus-monitor-ind + vs-profinet-monitor     │
│  vs-s7comm-monitor (write protection enabled)    │
└──────────┬───────────────────────────────────────┘
           │ Conduit (SL-3, dedicated hardware)
┌──────────▼───────────────────────────────────────┐
│  Safety Zone (SL-4)                              │
│  vs-iec61850-monitor (GOOSE replay detection)    │
│  Read-only mode enforced on all monitors         │
└──────────────────────────────────────────────────┘
```

### Key Principles

1. **Deploy at conduit boundaries.** Place Craton Shield on devices that bridge zones.
2. **Enforce least privilege.** Use `ReadOnly` function policies wherever possible.
3. **Block discovery protocols.** DCP, OPC UA FindServers, and similar should be blocked in production.
4. **Enable write protection.** Critical PLCs should only accept reads from the monitoring network.
5. **Monitor GOOSE/MMS in substations.** Replay and test-flag attacks are common IEC 61850 threats.

---

## IEC 62443 Compliance Assessment

Use the built-in compliance assessor to evaluate your deployment:

```rust
use vs_report_iec62443::{assess, SecurityLevel, SystemCapabilities};

let mut caps = SystemCapabilities::default();
caps.has_user_authentication = true;
caps.has_authorization_enforcement = true;
caps.has_cryptography = true;
caps.crypto_key_length_bits = 256;
caps.has_audit_logging = true;
// ... populate remaining fields ...

let report = assess(&caps, SecurityLevel::Sl3);
if !report.is_compliant() {
    // Review gaps
}
```

---

## Monitoring and Health

```rust
let health = shield.health_status();
// Per-protocol monitor health:
// health.modbus, health.opcua, health.profinet,
// health.ethernetip, health.dnp3, health.bacnet, ...

// Recent alerts:
let alerts = shield.recent_alerts();
```

---

## Further Reading

- [Core Deployment Guide](../../core/docs/deployment.md) — build profiles, initialization, watchdog
- [IEC 62443 Report Generator](../../core/report-iec62443/README.md) — compliance assessment
- [Porting Guide](../../core/docs/porting-guide.md) — HAL trait implementation
- [Feature Flags](../../core/docs/feature-flags.md) — all workspace features
- [Threat Model](../../core/docs/threat-model.md) — ICS threat scenarios
- [Performance Results](../../core/docs/performance-results.md) — protocol monitor latency
