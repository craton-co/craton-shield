# vs-runtime

Platform orchestrator for Craton Shield.

Ties together all subsystems (CAN monitor, Ethernet monitor, IDS engine,
firewall, policy engine, event logger, key manager, OTA validator, diagnostic
gateway (from `auto/`), integrity monitor, anomaly detector) into a single `CratonShield`
struct with a deterministic `tick()` / `submit_can_frame()` /
`submit_eth_packet()` interface.

## Key Types

| Type | Purpose |
|:-----|:--------|
| `CratonShield<C>` | Main platform struct, generic over `CryptoProvider` |
| `PlatformConfig` | Watchdog timeout, IDS window, diagnostic timeouts |
| `PlatformHealth` | 18-subsystem status snapshot |

## Lifecycle

```text
CratonShield::init(config, crypto)
    -> tick(timestamp_us)          // periodic housekeeping
    -> submit_can_frame(&frame, t) // CAN traffic
    -> submit_eth_packet(&pkt, t)  // Ethernet traffic
    -> health_status()             // subsystem health
    -> shutdown()                  // clean teardown
```

## Usage

```rust
use vs_runtime::{CratonShield, PlatformConfig};
use vs_crypto::SoftwareCryptoProvider;

let config = PlatformConfig::default();
let crypto = SoftwareCryptoProvider::default();
let mut vs = CratonShield::init(config, crypto).unwrap();

vs.tick(1_000_000).unwrap();
let health = vs.health_status();
```

## Feature Flags

See [docs/feature-flags.md](../../docs/feature-flags.md) for the full reference.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
