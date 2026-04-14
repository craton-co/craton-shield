# Installation Guide

## Prerequisites

### Required

- **Rust 1.82+** (MSRV — Minimum Supported Rust Version)
- **Cargo** (included with Rust)

```bash
# Install Rust via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Verify version
rustc --version   # must be >= 1.82.0
cargo --version
```

### Optional

| Tool | Purpose | Install |
|:-----|:--------|:--------|
| `thumbv7em-none-eabihf` target | `no_std` / Cortex-M4F builds | `rustup target add thumbv7em-none-eabihf` |
| `cargo-deny` | License and advisory auditing | `cargo install cargo-deny` |
| `cargo-fuzz` | Fuzz testing | `cargo install cargo-fuzz` |
| `cargo-llvm-cov` | Code coverage reporting | `cargo install cargo-llvm-cov` |
| A C compiler (gcc/clang) | Building the FFI example (`ffi_example.c`) | System package manager |

---

## Building from Source

### Clone the Repository

```bash
git clone https://github.com/craton-co/craton-shield.git
cd craton-shield
```

### Build the Full Workspace

```bash
# Debug build (faster compilation, larger binary)
cargo build --workspace

# Release build (optimized, suitable for benchmarking)
cargo build --workspace --release
```

### Build a Single Domain

```bash
# Core only
cargo build -p vs-runtime

# Automotive
cargo build -p vs-runtime-auto

# Embedded IoT
cargo build -p vs-runtime-embedded

# Industrial
cargo build -p vs-runtime-ind
```

### Build for Embedded Targets (no_std)

```bash
# Install the Cortex-M4F target
rustup target add thumbv7em-none-eabihf

# Check compilation (no test execution on bare-metal)
cargo check --target thumbv7em-none-eabihf -p vs-types -p vs-crypto -p vs-runtime

# Release build for embedded (smallest binary: panic=abort, LTO, opt-level=z)
cargo build --release --target thumbv7em-none-eabihf -p vs-runtime
```

---

## Running Tests

```bash
# Full workspace test suite
cargo test --workspace

# Per-domain tests
cargo test -p vs-can-monitor -p vs-eth-monitor -p vs-ids-engine    # Core IDS
cargo test -p vs-runtime-auto -p vs-signal-ids -p vs-v2x           # Automotive
cargo test -p vs-runtime-embedded -p vs-mqtt-monitor -p vs-coap-monitor  # Embedded IoT
cargo test -p vs-runtime-ind -p vs-modbus-monitor-ind -p vs-opcua-monitor  # Industrial

# Integration tests
cargo test --test attack_scenarios

# Benchmarks
cargo bench --workspace
```

---

## Feature Flags

Feature flags control optional functionality and capacity tiers. Key flags:

| Flag | Crate(s) | Description |
|:-----|:---------|:------------|
| `mock-hsm` | `vs-crypto` | Software HSM mock for testing. **Never enable in production.** |
| `software` | `vs-crypto` | Production-ready RustCrypto-based provider |
| `pq` | `vs-crypto` | Post-quantum cryptography (ML-KEM-768, ML-DSA-65) |
| `capacity-large` | Multiple | Increased capacity limits (2x base) |
| `capacity-xl` | Multiple | Maximum capacity limits (4x base) |
| `std` | `vs-storage` | Filesystem-backed storage (requires `std`) |

See [core/docs/feature-flags.md](core/docs/feature-flags.md) for the complete reference.

---

## Verification

After building, verify your installation:

```bash
# Lint check
cargo clippy --workspace --all-targets -- -D warnings

# Format check
cargo fmt --all -- --check

# no_std check
cargo check --target thumbv7em-none-eabihf -p vs-types -p vs-crypto -p vs-runtime

# Security audit
cargo deny check

# Build documentation
cargo doc --workspace --no-deps --open
```

---

## Local CI

A script that mirrors the GitHub Actions CI pipeline is provided:

```bash
./scripts/local-ci.sh --fast    # Quick check (fmt, clippy, test)
./scripts/local-ci.sh           # Full check (includes no_std, audit, deny, docs)
```

---

## Next Steps

- [Quick Start (README)](README.md#quick-start) — minimal usage example
- [Architecture](core/docs/architecture.md) — system design overview
- [Deployment Guide](core/docs/deployment.md) — production deployment on embedded targets
- [Porting Guide](core/docs/porting-guide.md) — implementing HAL traits for new platforms
- [Hardware Compatibility](core/docs/hardware-compatibility.md) — tested and compatible targets
- [Contributing](CONTRIBUTING.md) — development setup and coding standards
