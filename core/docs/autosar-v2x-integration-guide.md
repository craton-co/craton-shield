# AUTOSAR & V2X Integration Guide

> **Note:** The `vs-autosar` and `vs-v2x` crates referenced in this guide are available in the [`auto/`](../../auto/) directory. This guide documents integration patterns for use with Craton Shield Core.

## AUTOSAR Integration

### 1. SecOC Setup

Register PDUs with `SecOcManager`, specifying the CAN ID, HMAC key slot,
truncated MAC length, and freshness value size:

```rust
use vs_autosar::{SecOcManager, SecOcPduConfig, SecOcDirection};

let mut secoc = SecOcManager::new(my_crypto, /* default_max_age_us */ 100_000);

let brake_cfg = SecOcPduConfig {
    can_id: 0x120,
    key_id: 1,
    mac_len: 4,        // 4-byte truncated HMAC
    freshness_len: 2,  // 2-byte counter
    direction: SecOcDirection::Rx,
    active: true,
};
let slot = secoc.register_pdu(brake_cfg)?;
```

Verify incoming frames with `verify_rx`, which checks freshness monotonicity
and the truncated MAC. Prepare outbound frames with `prepare_tx`, which
appends the freshness counter and computed MAC:

```rust
let result = secoc.verify_rx(&incoming_frame, now_us);
// For Tx: writes freshness + MAC starting at auth_data_len
let new_dlc = secoc.prepare_tx(&mut tx_frame, auth_data_len, now_us)?;
```

### 2. IdsM Integration

`IdsmReporter` converts Craton Shield `SecurityAlert` values into AUTOSAR
IdsM events queued for the Dem/IdsM stack. Severity maps automatically
(`Info`->`Sev0` through `Critical`->`Sev4`):

```rust
use vs_autosar::{IdsmReporter, SecOcVerifyResult};

let mut idsm = IdsmReporter::new();

// Report a Craton Shield alert
let seq = idsm.report_alert(&alert)?;

// Report a SecOC failure directly
idsm.report_secoc_failure(0x120, SecOcVerifyResult::MacMismatch, now_us)?;

// Drain events into the AUTOSAR IdsM stack
while let Some(event) = idsm.dequeue() {
    autosar_idsm_report(event.event_type, event.severity, event.source_id);
}
```

### 3. MCAL Adapter Usage

Implement `McalCanDriver` to bridge your AUTOSAR Classic MCAL CAN driver,
then wrap it with `McalCanAdapter` to satisfy the Craton Shield `CanBus` HAL:

```rust
use vs_autosar::{McalCanDriver, McalCanAdapter, McalCanStatus};
use vs_hal::RawCanFrame;

struct MyMcalCan { /* bindings to Can_Write / Can_MainFunction_Read */ }

impl McalCanDriver for MyMcalCan {
    fn can_main_function_read(&mut self) -> Option<RawCanFrame> { /* ... */ }
    fn can_write(&mut self, frame: &RawCanFrame) -> Result<(), VsError> { /* ... */ }
    fn can_get_bitrate(&self) -> u32 { 500_000 }
    fn can_get_status(&self) -> McalCanStatus { McalCanStatus::Ready }
}

// The adapter implements vs_hal::CanBus and can be passed to Craton Shield
let can_bus = McalCanAdapter::new(MyMcalCan { /* ... */ });
```

The same pattern applies for Ethernet via `McalEthDriver` / `McalEthAdapter`,
which satisfies `EthernetPhy`.

### 4. Ara::com Service Discovery

Use `ServiceRegistry` to register SOME/IP services and monitor the service
landscape for rogue advertisements:

```rust
use vs_autosar::ServiceRegistry;

let mut registry = ServiceRegistry::new();
let slot = registry.register(
    0x1234,  // service_id
    0x0001,  // instance_id
    1,       // major_version
    0,       // minor_version
)?;
registry.offer(slot)?;

// Look up a discovered service
if let Some((idx, inst)) = registry.find(0x1234, 0x0001) {
    assert_eq!(inst.state, vs_autosar::ServiceState::Offered);
}
```

---

## V2X Integration

### 1. V2xValidator Setup

Create a validator with the default limits (250 km/h max speed, 5 s max age)
or supply custom `PlausibilityLimits`:

```rust
use vs_v2x::{V2xValidator, PlausibilityLimits};

// Default limits
let mut validator = V2xValidator::new(crypto_provider);

// Custom limits for low-speed urban zones
let limits = PlausibilityLimits {
    max_speed_cm_s: 8_334,      // ~83 km/h (50 mph)
    max_age_us: 2_000_000,      // 2 seconds
    max_future_us: 500_000,     // 0.5 s clock skew tolerance
    ..PlausibilityLimits::default()
};
let mut validator = V2xValidator::with_limits(crypto_provider, limits);
```

### 2. Message Validation Flow

Every message passes through three checks in order:
1. **Plausibility** -- speed, heading, lat/lon range, and timestamp freshness.
2. **Signature** -- ECDSA P-256 verification over a SHA-256 digest.
3. **Replay** -- 256-entry ring-buffer cache of message digests.

```rust
use vs_v2x::{V2xMessage, ValidatedV2xMessage};

let result: Result<ValidatedV2xMessage, VsError> =
    validator.validate(&incoming_msg, current_time_us);

match result {
    Ok(validated) => {
        let payload = validated.payload();
        // Forward to application layer -- type-safe guarantee of validation
    }
    Err(VsError::AuthenticationFailure) => { /* bad signature */ }
    Err(VsError::PolicyViolation)      => { /* plausibility or replay */ }
    Err(VsError::Timeout)             => { /* stale or future timestamp */ }
    Err(e)                            => { /* other crypto error */ }
}
```

### 3. IDS Pipeline Integration

Feed validated V2X messages into the IDS engine by converting them to CAN-like
alert events. Rejected messages should be reported through the IdsM reporter:

```rust
if let Err(e) = validator.validate(&msg, now_us) {
    let alert = SecurityAlert {
        severity: AlertSeverity::High,
        bus: BusType::AutomotiveEthernet,
        source_id: 0,
        timestamp_us: now_us,
        payload_hash: [0u8; 32],
    };
    idsm_reporter.report_alert(&alert)?;
}

// Check counters for telemetry
let accepted = validator.validated_count();
let rejected = validator.rejected_count();
```

### 4. Testing with the `stub` Feature

Enable the `stub` feature in dev/test builds to bypass all V2X validation.
A compile-time error prevents accidental use in release builds:

```toml
# Cargo.toml
[dev-dependencies]
vs-v2x = { path = "crates/v2x", features = ["stub"] }
```

```rust
#[cfg(test)]
mod tests {
    // With `stub` enabled, validate() accepts all messages --
    // useful for integration tests that focus on downstream logic.
    let mut validator = V2xValidator::new(test_crypto);
    let result = validator.validate(&any_message, 0);
    assert!(result.is_ok());
}
```

> **Warning:** The `stub` feature compiles only under `debug_assertions`.
> Attempting to build with `--release` and `stub` enabled triggers a
> `compile_error!`.
