# Feature Flags Reference

> Craton Shield 0.7.0

## Crypto Features (`vs-crypto`)

| Flag | Default | Description |
|------|---------|-------------|
| `mock-hsm` | off | Enables a software mock of the HSM interface for testing. Activated automatically in `#[cfg(test)]`. **Never enable in production.** |
| `pq-software` | off | Enables post-quantum key encapsulation (ML-KEM) and digital signatures (ML-DSA/FIPS 204) via software. Adds `ml-kem` and `fips204` dependencies. **Status (0.7.0):** Software provider is available for testing and development. Hardware HSM integration is in progress — do not use in production safety-critical paths until a concrete HSM-backed provider is qualified. See roadmap Phase 3 for timeline. |

```toml
# Example: enable both for development
vs-crypto = { path = "crates/crypto", features = ["mock-hsm", "pq-software"] }
```

## Serialization Features (`vs-ota-validator`)

| Flag | Default | Description |
|------|---------|-------------|
| `json` | off | Enables JSON parsing of OTA metadata using `serde` + `serde-json-core` (no_std compatible). Required for TUF metadata ingestion from update servers. |

```toml
vs-ota-validator = { path = "crates/ota-validator", features = ["json"] }
```

## Testing Feature (`vs-can-monitor`)

| Flag | Default | Description |
|------|---------|-------------|
| `testing` | off | Exposes a deterministic `Default` impl for `CanMonitor` so that tests and fuzz harnesses can construct a monitor without real keys. Activated alongside `#[cfg(test)]`. **Never enable in production.** |

```toml
vs-can-monitor = { path = "crates/can-monitor", features = ["testing"] }
```

## Capacity Features (`vs-netfw`, `vs-runtime`, `vs-storage`)

Three crates support graduated capacity tiers to trade RAM for rule/entry count. The tiers are mutually exclusive — enabling a higher tier overrides the lower one.

| Flag | Default | `vs-netfw` rules | `vs-runtime` subsystems | `vs-storage` entries |
|------|---------|-----------------|------------------------|---------------------|
| *(none)* | **yes** | Base | Base | Base |
| `capacity-large` | off | Expanded | Expanded | Expanded |
| `capacity-xl` | off | Maximum | Maximum | Maximum |

The selection logic uses a priority pattern:

```rust
#[cfg(feature = "capacity-xl")]
const MAX: usize = /* largest */;

#[cfg(all(feature = "capacity-large", not(feature = "capacity-xl")))]
const MAX: usize = /* medium */;

#[cfg(not(any(feature = "capacity-large", feature = "capacity-xl")))]
const MAX: usize = /* base */;
```

## Standard Library Feature (`vs-storage`)

| Flag | Default | Description |
|------|---------|-------------|
| `std` | off | Enables `std` library support in the storage crate. Only use for host-side tooling, never on embedded targets. |

## Encrypted Storage Feature (`vs-storage`)

| Flag | Default | Description |
|------|---------|-------------|
| `encrypted` | off | Enables encrypted storage support. Pulls in `vs-crypto` as a dependency for encryption operations. |

```toml
vs-storage = { path = "crates/storage", features = ["encrypted"] }
```

## Workspace Feature (root `Cargo.toml`)

| Flag | Default | Description |
|------|---------|-------------|
| `wcet` | off | Enables the worst-case execution time analysis harness (`wcet-harness` binary). Pulls in vs-types, vs-crypto, vs-can-monitor, vs-eth-monitor, vs-netfw, vs-policy-engine, vs-event-logger, vs-runtime. |

```bash
# Build the WCET harness
cargo build --bin wcet-harness --features wcet --release
```

## CI Feature Matrix

The CI pipelines enable features as follows:

| CI Job | Features |
|--------|----------|
| `fmt` | none |
| `test` (x86_64 + aarch64) | `mock-hsm`, `pq-software`, `testing`, `json` |
| `check-thumbv7em` | none (base capacity) |
| `test-hal-linux` | none |
| `coverage` | `mock-hsm`, `pq-software`, `testing`, `json` |
| `doc` | none |
| `security-audit` | none |
| `deny` | none |
| `miri` | `mock-hsm`, `testing` |
| `fuzz` | none |
| `ffi-validation` | none |
| `test-windows` | `mock-hsm`, `pq-software`, `testing` |
| `msrv` | none |

## Adding a New Feature Flag

1. Define in the crate's `Cargo.toml` under `[features]`
2. Gate code with `#[cfg(feature = "...")]`
3. Add to this document
4. Add a CI job or matrix entry in `.github/workflows/ci.yml`
5. Ensure the flag compiles on all targets: x86_64, aarch64, thumbv7em
