# Craton Shield -- Architecture Document

**Document Version**: 1.0.0 | **Date**: 2026-03-15 | **Classification**: ASIL-B
**Software Version**: 0.7.0

> **Note:** The document version (1.0.0) tracks the revision of this architecture document and follows its own versioning cycle, independent of the Craton Shield software version (0.7.0).

---

## 1 Executive Summary

Craton Shield is a `#![no_std]`, zero-heap embedded security runtime implemented in Rust.
While initially targeting automotive intrusion detection and prevention, the core
architecture — modular crates, static allocation, ~280 KiB footprint (Standard tier), trait-based HAL — is
designed as a universal security primitive stack for any Cortex-M3+ device with 256 KB+
of flash. Domain-specific modules (CAN IDS, UDS Diagnostics, AUTOSAR) are adapter crates
that sit atop a portable security core applicable to industrial, medical, energy, and
defense embedded systems.

The core layer is organized as a 21-crate Cargo workspace within the larger 47-crate multi-domain workspace (see root README for the full domain breakdown) with a strict layered dependency
model. Each layer may depend only on layers below it, and all hardware interaction is
abstracted behind traits so the platform can target bare-metal Cortex-M, Cortex-A, Linux,
AUTOSAR Classic/Adaptive, and RTOS environments without source-level changes.

This document describes the layered architecture, crate dependency graph, data flow
through the system, security boundaries, and core design principles.

> **Formalization note (ISO 26262-6 Table 1):** The architecture diagram in
> `architecture.svg` provides a visual overview. For formal ASIL-B certification,
> this diagram should be supplemented with:
> - A SysML Block Definition Diagram (BDD) showing crate boundaries and interfaces
> - A SysML Internal Block Diagram (IBD) showing data flow between subsystems
> - A formal interface specification for each HAL trait (see Section 4)
>
> These artifacts are tracked in the ISO 26262 pre-assessment
> (`docs/certification/iso-26262-asil-b-assessment.md`, gap item "Architecture
> formal diagrams").

---

## 2 Layered Architecture

The workspace is organized into four layers. Dependencies flow strictly downward.

```
+======================================================================+
|  Layer 3 -- INTEGRATION                                              |
|                                                                      |
|   vs-ids-engine       vs-runtime           vs-ffi                    |
|   (correlation)       (orchestrator)       (C ABI export)            |
+======================================================================+
        |                     |                    |
        v                     v                    v
+======================================================================+
|  Layer 2 -- CORE SUBSYSTEMS                                          |
|                                                                      |
|   vs-crypto           vs-anomaly          vs-can-monitor             |
|   vs-eth-monitor      vs-netfw            vs-policy-engine           |
|   vs-event-logger     vs-integrity        vs-key-manager             |
|   vs-ota-validator    vs-secure-boot      vs-storage                 |
|                                                                      |
|  Layer 2b -- COMPLIANCE AUTOMATION                                   |
|                                                                      |
|   vs-report-iec62443  vs-report-iso21434  vs-report-iec62304         |
+======================================================================+
        |                     |                    |
        v                     v                    v
+======================================================================+
|  Layer 1 -- HARDWARE ABSTRACTION LAYER (HAL)                         |
|                                                                      |
|   vs-hal              vs-hal-linux                                   |
|   (trait defs)        (Linux impl)                                   |
+======================================================================+
        |                     |
        v                     v
+======================================================================+
|  Layer 0 -- TYPES                                                    |
|                                                                      |
|   vs-types                                                           |
|   (shared enums, structs, error types, constants)                    |
+======================================================================+
```

### Layer 0 -- Types (`vs-types`)

Foundation crate with zero dependencies. Defines all shared data structures: CAN frame
representation, Ethernet packet header, alert severity levels, error enums, configuration
constants, and timestamp types.

### Layer 1 -- HAL (`vs-hal`, `vs-hal-linux`)

`vs-hal` defines the hardware abstraction traits. `vs-hal-linux` provides a concrete
implementation for Linux/POSIX targets used in development, CI, and HILS testing.

### Layer 2 -- Core Subsystems

Twelve core crates that implement the security monitoring, cryptographic, and management
functions. Each crate depends only on `vs-types` and `vs-hal` (trait bounds, not concrete
implementations).

In addition, three compliance-automation report crates (`vs-report-iec62443`,
`vs-report-iso21434`, `vs-report-iec62304`) also reside in Layer 2. These are
utility crates that generate safety/security compliance reports and depend only on
`vs-types` (Layer 0). Together with the twelve core crates, Layer 2 contains 15 crates
in total.

> **Note:** Additional automotive-specific crates (signal-ids, diag-gateway, v2x, autosar) are available in the [`auto/`](../../auto/) directory. Industrial and embedded IoT crates are in [`industrial/`](../../industrial/) and [`embedded/`](../../embedded/) respectively.

### Layer 3 -- Integration

Three crates that compose the subsystems into a running system. `vs-ids-engine`
correlates alerts from multiple monitors. `vs-runtime` orchestrates initialization, tick
scheduling, and health reporting. `vs-ffi` exports the C-ABI surface for integration into
C/C++ ECU software.

---

## 3 Dependency Graph

Arrows indicate "depends on". Each crate is listed with its layer.

```
vs-ffi [L3]
  |
  +---> vs-runtime [L3]
  |       |
  |       +---> vs-ids-engine [L3]
  |       |       |
  |       |       +---> vs-can-monitor [L2]
  |       |       |       +---> vs-anomaly [L2]
  |       |       |       |       +---> vs-types [L0]
  |       |       |       +---> vs-hal [L1]
  |       |       |       +---> vs-types [L0]
  |       |       |
  |       |       +---> vs-eth-monitor [L2]
  |       |       |       +---> vs-netfw [L2]
  |       |       |       |       +---> vs-types [L0]
  |       |       |       +---> vs-hal [L1]
  |       |       |       +---> vs-types [L0]
  |       |       |
  |       |       +---> vs-event-logger [L2]
  |       |       |       +---> vs-storage [L2]
  |       |       |       |       +---> vs-hal [L1]
  |       |       |       |       +---> vs-types [L0]
  |       |       |       +---> vs-types [L0]
  |       |       |
  |       |       +---> vs-types [L0]
  |       |
  |       +---> vs-crypto [L2]
  |       |       +---> vs-hal [L1]
  |       |       +---> vs-types [L0]
  |       |
  |       +---> vs-key-manager [L2]
  |       |       +---> vs-crypto [L2]
  |       |       +---> vs-hal [L1]
  |       |       +---> vs-types [L0]
  |       |
  |       +---> vs-ota-validator [L2]
  |       |       +---> vs-crypto [L2]
  |       |       +---> vs-hal [L1]
  |       |       +---> vs-types [L0]
  |       |
  |       +---> vs-secure-boot [L2]
  |       |       +---> vs-crypto [L2]
  |       |       +---> vs-integrity [L2]
  |       |       |       +---> vs-hal [L1]
  |       |       |       +---> vs-types [L0]
  |       |       +---> vs-types [L0]
  |       |
  |       +---> vs-policy-engine [L2]
  |       |       +---> vs-types [L0]
  |       |
  |       +---> vs-hal [L1]
  |       +---> vs-types [L0]
  |
  +---> vs-types [L0]
```

### Compliance Report Crates (Layer 2b)

```
vs-report-iec62443 [L2]
  +---> vs-types [L0]

vs-report-iso21434 [L2]
  +---> vs-types [L0]

vs-report-iec62304 [L2]
  +---> vs-types [L0]
```

### HAL Implementation Selection

```
vs-hal-linux [L1]
  +---> vs-hal [L1]
  +---> vs-types [L0]
```

`vs-hal-linux` is selected at link time via Cargo features and is never compiled into
production firmware. OEM-specific HAL crates (not in this workspace) implement the same
traits for their target hardware.

---

## 4 Data Flow Diagrams

### 4.1 CAN Frame Processing

```
  CAN Bus
    |
    | (raw frame via HAL CanBus trait)
    v
+------------------+
| vs-can-monitor   |   process_frame(frame)
|   +- vs-anomaly  |   -> frequency EWMA, z-score
+------------------+
    |
    | CanAlert { id, severity, kind }
    v
+------------------+
| vs-ids-engine    |   correlate(alert)
|                  |   -> cross-domain correlation
+------------------+
    |
    | SecurityAlert { source, severity, detail }
    v
+------------------+
| vs-event-logger  |   log_event(alert)
|   +- vs-storage  |   -> ring buffer in flash / RAM
+------------------+
    |
    | (telemetry via FFI callback or shared memory)
    v
  VSOC / DTC Handler
```

### 4.2 Ethernet Packet Processing

```
  Ethernet PHY
    |
    | (raw packet via HAL EthernetPhy trait)
    v
+------------------+
| vs-eth-monitor   |   inspect_packet(packet)
|                  |   -> SOME/IP header parse
|                  |   -> service discovery tracking
+------------------+
    |
    | EthAction { packet, verdict }
    v
+------------------+
| vs-netfw         |   evaluate(packet)
|                  |   -> rule table lookup
|                  |   -> default-deny enforcement
+------------------+
    |
    | Verdict::Allow / Verdict::Deny
    |
    +--- if Deny ---> drop packet, emit EthAlert
    |
    +--- if Alert ---> vs-ids-engine (correlation)
    |
    v
  Forward to destination (via HAL)
```

### 4.3 Runtime Tick Cycle

```
  Integrator calls tick(timestamp)
    |
    v
+------------------+
| vs-runtime       |
|                  |
|  1. Read CAN RX  +---> vs-can-monitor::process_frame()
|  2. Read ETH RX  +---> vs-eth-monitor::inspect_packet()
|  3. Correlate    +---> vs-ids-engine::correlate()
|  4. Log events   +---> vs-event-logger::flush()
|  5. Health check +---> PlatformHealth update
|  6. OTA poll     +---> vs-ota-validator::poll()
|                  |
+------------------+
    |
    v
  Return PlatformHealth to integrator
```

---

## 5 Key Traits (Abstraction Interfaces)

The core architecture relies on trait-based abstraction at multiple layers. HAL traits
(`CanBus`, `Timer`, `HsmHardware`, `EthernetPhy`) are defined in `vs-hal` (Layer 1).
Domain traits (`CryptoProvider`, `StorageProvider`) are defined in their respective
Layer 2 crates (`vs-crypto`, `vs-storage`). Concrete implementations are injected at
compile time.

```
trait CryptoProvider {
    fn aes_gcm_encrypt(key, nonce, aad, plaintext, out) -> Result<usize, CryptoError>;
    fn aes_gcm_decrypt(key, nonce, aad, ciphertext, out) -> Result<usize, CryptoError>;
    fn sha256(data) -> [u8; 32];
    fn hmac_sha256(key, data) -> [u8; 32];
    fn ecdsa_p256_sign(key, digest) -> Result<Signature, CryptoError>;
    fn ecdsa_p256_verify(pubkey, digest, sig) -> Result<bool, CryptoError>;
    fn ecdh_p256(private, peer_public) -> Result<SharedSecret, CryptoError>;
}

trait CanBus {
    fn receive(&mut self) -> Result<Option<RawCanFrame>, VsError>;
    fn transmit(&mut self, frame: &RawCanFrame) -> Result<(), VsError>;
}

trait Timer {
    fn now_us(&self) -> u64;
    fn cycle_count(&self) -> Option<u64>;
}

trait HsmHardware {
    fn store_key(slot: u8, material: &[u8]) -> Result<(), HalError>;
    fn load_key(slot: u8, out: &mut [u8]) -> Result<usize, HalError>;
    fn delete_key(slot: u8) -> Result<(), HalError>;
}

trait EthernetPhy {
    fn receive(&mut self, buf: &mut [u8]) -> Result<usize, VsError>;
    fn transmit(&mut self, buf: &[u8]) -> Result<(), VsError>;
}

trait StorageProvider {
    fn read(region: StorageRegion, offset: u32, buf: &mut [u8]) -> Result<usize, HalError>;
    fn write(region: StorageRegion, offset: u32, data: &[u8]) -> Result<(), HalError>;
    fn erase(region: StorageRegion) -> Result<(), HalError>;
}
```

---

## 6 Security Boundaries

```
+-----------------------------------------------------------------------+
|  ECU Process Space                                                    |
|                                                                       |
|  +----------------------------+   +-----------------------------+     |
|  | TRUSTED CORE               |   | UNTRUSTED INPUT             |     |
|  |                            |   |                             |     |
|  | vs-runtime                 |   | CAN bus (external)          |     |
|  | vs-crypto (key material)   |   | Ethernet (external)         |     |
|  | vs-key-manager             |   | OTA update images           |     |
|  | vs-secure-boot             |   |                             |     |
|  +----------------------------+   +-----------------------------+     |
|        |                                    |                         |
|        | (all input validated               |                         |
|        |  before crossing                   |                         |
|        |  boundary)                         |                         |
|        v                                    v                         |
|  +----------------------------+   +-----------------------------+     |
|  | VALIDATION BOUNDARY        |   | OUTPUT BOUNDARY             |     |
|  |                            |   |                             |     |
|  | vs-can-monitor (parse)     |   | vs-event-logger (alerts)    |     |
|  | vs-eth-monitor (parse)     |   | vs-ffi (C callbacks)        |     |
|  | vs-netfw (rule eval)       |   | PlatformHealth (status)     |     |
|  | vs-ota-validator (sig)     |   |                             |     |
|  +----------------------------+   +-----------------------------+     |
+-----------------------------------------------------------------------+
```

**Boundary rules:**

1. No untrusted data reaches the trusted core without passing through a validation
   component.
2. Key material never crosses the output boundary (keys are zeroized on drop).
3. The FFI boundary enforces opaque handles; callers cannot access internal state.
4. All parsing of external data uses bounded reads with explicit length checks.

---

## 7 Design Principles

### 7.1 `#![no_std]` Throughout

Every production crate is `#![no_std]`. The standard library is never linked into
firmware builds. This ensures the platform can run on bare-metal targets without an OS.

### 7.2 Zero Heap Allocation

No crate uses `alloc`. All data structures use fixed-size arrays and ring buffers sized
by compile-time constants. This eliminates heap fragmentation, non-deterministic
allocation latency, and out-of-memory panics.

### 7.3 Trait-Based HAL

All hardware interaction flows through traits defined in `vs-hal`. This provides:
- Compile-time dispatch (monomorphization, no vtable overhead)
- Target portability without `#[cfg]` in business logic
- Testability via mock implementations in unit tests

### 7.4 Default-Deny Security Model

- The network firewall denies all traffic not matched by an explicit allow rule.
- The OTA validator rejects all images without a valid signature chain.
- Unknown CAN arbitration IDs generate alerts by default.

### 7.5 No Panics in Production Code

All fallible operations return `Result` or use saturating/wrapping arithmetic.
`#![deny(clippy::panic)]` and `#![deny(clippy::unwrap_used)]` are enforced across the
workspace. This supports ASIL-B requirements for deterministic behavior.

### 7.6 Bounded Execution Time

All loops have compile-time upper bounds. No recursion is used. This enables WCET
analysis and ensures the runtime tick completes within its deadline.
