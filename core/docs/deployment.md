# Deployment Guide

> Craton Shield 0.7.0

This guide covers operational deployment of Craton Shield on production embedded
targets — automotive ECUs, industrial controllers, medical devices, or any
Cortex-M3+ system with 256 KB+ flash. For HAL implementation, see the
[Porting Guide](porting-guide.md). For integration assumptions, see the
[Safety Manual](safety-manual.md).

## Build Configuration

### Release Profile

Use the `release` or `release-safe` profile for production builds:

```bash
# Smallest binary (panic=abort, LTO, opt-level=z)
cargo build --release --target thumbv7em-none-eabihf

# With overflow checks (recommended for ASIL-B)
cargo build --profile release-safe --target thumbv7em-none-eabihf
```

### Feature Selection

| Deployment scenario | Recommended features |
|:--------------------|:---------------------|
| Embedded gateway (no HSM) | `mock-hsm` **off**, `capacity-large` |
| Embedded gateway (with HSM) | defaults (base capacity) |
| Linux gateway (NXP S32G3) | `std` on vs-storage, `capacity-xl` |
| Test/CI only | `mock-hsm`, `pq-software` |

**Never** enable `mock-hsm` in production. It provides no real cryptographic
security.

## Initialization Sequence

The runtime must be initialized in a specific order. See
[Safety Manual, Section 4.2](safety-manual.md) for the full 7-step sequence.

```rust
let config = PlatformConfig {
    watchdog_timeout_us: 1_000_000,   // 1 second
    watchdog_action: WatchdogAction::Reset,
    ids_correlation_window_us: 100_000, // 100 ms
    diag_session_timeout_us: 5_000_000, // 5 seconds
    diag_lockout_duration_us: 10_000_000, // 10 seconds
};
let mut vs = CratonShield::init(config, crypto_provider)?;
```

## Monitoring

### Health Checks

Poll `health_status()` periodically (recommended: every tick cycle).

```rust
let health = vs.health_status();
// Check all subsystems are Ready
if health.crypto != SubsystemStatus::Ready {
    // Crypto subsystem degraded — escalate
}
```

All core subsystem statuses are reported. Map these to your platform's
diagnostic trouble codes (DTCs) or health monitoring framework.
Additional subsystems (diagnostic gateway, V2X, telemetry) are available in
[auto/](../../auto/).

### Capacity Monitoring

The runtime reports capacity utilization at the 90% threshold. Monitor
`event_log_count()` to detect approaching ring-buffer wrap-around. When the
event log wraps, the oldest entries are overwritten.

### Alert Routing

Security alerts are routed through the IDS engine with severity levels:
`Info`, `Low`, `Medium`, `High`, `Critical`. Map these to your VSOC
(Vehicle Security Operations Center) or telemetry pipeline:

| Severity | Recommended action |
|:---------|:-------------------|
| Info | Log locally |
| Low | Log + periodic telemetry upload |
| Medium | Log + immediate telemetry upload |
| High | Log + telemetry + driver/fleet notification |
| Critical | Log + telemetry + consider safe-stop procedure |

## Watchdog

Configure the watchdog timeout based on your tick interval. The watchdog
fires if `tick()` is not called within `watchdog_timeout_us` microseconds.

| Action | Behavior |
|:-------|:---------|
| `WatchdogAction::Reset` | Platform enters reset state (recommended) |
| `WatchdogAction::LogOnly` | Log the timeout, continue running |

## Update Procedures

### OTA Updates

Use the `OtaValidator` to verify firmware images before flashing:

1. Verify TUF root metadata signatures (threshold-based)
2. Check metadata expiration against current time
3. Verify target hash and length against the firmware blob
4. Check rollback counter (version must be strictly increasing)

### Key Rotation

Use the `KeyManager` to rotate cryptographic keys. All key operations are
audit-logged. Keys are zeroized on drop.

## Decommissioning

Before decommissioning an ECU:

1. Call `vs.shutdown()` to cleanly stop all subsystems
2. Zeroize all key material (automatic via `KeyManager::drop()`)
3. Erase persistent storage contents
4. Clear the event log

See [Safety Manual, Section 10](safety-manual.md) for the full
decommissioning procedure.

## Operational Constraints

| Constraint | Value | Reference |
|:-----------|:------|:----------|
| Max CAN frame processing latency | 50 us WCET budget | SSR-01 |
| Max concurrent diagnostic sessions | 4 | vs-diag-gateway (auto/) |
| Brute-force lockout threshold | 3 attempts | vs-diag-gateway (auto/) |
| Event log entry size | 210 bytes fixed | vs-event-logger |
| Firewall rule evaluation | Priority-ordered, first match | vs-netfw |
