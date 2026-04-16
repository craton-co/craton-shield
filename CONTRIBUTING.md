# Contributing to Craton Shield

Thank you for your interest in contributing to Craton Shield! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Developer Certificate of Origin (DCO)](#developer-certificate-of-origin-dco)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Security Vulnerabilities](#security-vulnerabilities)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to [security@craton.com.ar](mailto:security@craton.com.ar).

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally
3. Create a feature branch from `main`
4. Make your changes
5. Submit a pull request

## Developer Certificate of Origin (DCO)

All contributions to Craton Shield must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/) (DCO). This certifies that you have the right to submit your contribution under the project's open-source license.

### How to Sign Off

Add a `Signed-off-by` line to your commit messages:

```
feat(crypto): add streaming SHA-256 interface

Signed-off-by: Your Name <your.email@example.com>
```

You can do this automatically with `git commit -s`.

### Why DCO?

The DCO is a lightweight alternative to a Contributor License Agreement (CLA). It ensures all contributions are properly licensed without requiring a separate legal agreement. This is especially important for a security-critical project like Craton Shield.

## Development Setup

### Prerequisites

- **Rust 1.82+** (MSRV)
- `thumbv7em-none-eabihf` target for `no_std` validation
- (Optional) `cargo-deny` for license/advisory checks
- (Optional) `cargo-fuzz` for fuzz testing

### Building

```bash
# Install Rust (if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install no_std target
rustup target add thumbv7em-none-eabihf

# Build the entire workspace
cargo build --workspace

# Run all tests
cargo test --workspace

# Run the local CI script (mirrors GitHub Actions)
./scripts/local-ci.sh --fast

# Or run the same checks inside Docker (matches CI's Linux runner)
./scripts/local-ci-docker.sh --fast
```

### Workspace Structure

```
core/           Core security primitives (21 crates)
auto/           Automotive-specific crates (7 crates)
embedded/       Embedded IoT crates (8 crates)
industrial/     Industrial OT/ICS crates (11 crates)
```

Each crate has its own `Cargo.toml` and `README.md`. All crates inherit workspace-level settings from the root `Cargo.toml`.

**Naming convention:** Cargo package names use a `vs-` prefix (e.g., `vs-crypto`, `vs-can-monitor`) while directory names use bare names (e.g., `core/crypto`, `core/can-monitor`). Use the `vs-` prefixed name with Cargo commands (`cargo test -p vs-crypto`) and the directory path for file system operations.

## Making Changes

### Branch Naming

Use descriptive branch names:

- `feat/add-someip-monitor` -- new feature
- `fix/nonce-tracker-overflow` -- bug fix
- `docs/update-porting-guide` -- documentation
- `test/add-modbus-coverage` -- test improvements
- `refactor/simplify-policy-eval` -- refactoring

### Commit Messages

Write clear, descriptive commit messages:

```
<type>(<scope>): <short summary>

<optional body explaining the why, not the what>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `ci`, `chore`

Examples:
```
feat(crypto): add streaming SHA-256 interface
fix(netfw): correct rate limiter bucket refill at overflow
docs(porting): add QNX 7.1 cross-compilation instructions
test(modbus-ind): add CRC validation test vectors
```

## Coding Standards

### Rust Style

- **Format:** Run `cargo fmt --all` before committing. CI enforces `cargo fmt --check`.
- **Lints:** All code must pass `cargo clippy --workspace --all-targets -- -D warnings`. Clippy pedantic is enabled workspace-wide.
- **`unsafe` code:** Forbidden workspace-wide (`unsafe_code = "deny"`). The only exception is `core/ffi/` which provides the C FFI boundary. Any new `unsafe` code requires detailed safety comments and review from a maintainer.

### `no_std` Requirements

All crates in the workspace must compile for `thumbv7em-none-eabihf` (Cortex-M4F). This means:

- **No heap allocation.** Use fixed-capacity arrays and stack-allocated structures.
- **No `std` imports.** Use `core::` and `alloc::` only where explicitly enabled.
- **No floating point** in core crates (soft-float target).

### Security Requirements

- Use `subtle::ConstantTimeEq` for all security-sensitive comparisons
- Zeroize sensitive data on drop using the `zeroize` crate
- Never log or display key material, nonces, or plaintext
- All input from external sources must be validated before use
- Follow the [threat model](core/docs/threat-model.md) for security design decisions

### Documentation

- All `pub` items must have `///` doc comments
- Module-level documentation (`//!`) is required for new crates
- Update relevant docs in `core/docs/` when changing behavior
- Add or update examples in `core/examples/` for significant features

## Testing

### Running Tests

```bash
# All tests
cargo test --workspace

# Specific crate
cargo test -p vs-crypto

# Per-domain tests
cargo test -p vs-can-monitor -p vs-eth-monitor -p vs-ids-engine    # Core IDS
cargo test -p vs-runtime-auto -p vs-signal-ids -p vs-v2x           # Automotive
cargo test -p vs-runtime-embedded -p vs-mqtt-monitor -p vs-coap-monitor  # Embedded IoT
cargo test -p vs-runtime-ind -p vs-modbus-monitor-ind -p vs-opcua-monitor  # Industrial

# Integration tests only
cargo test --test attack_scenarios

# With output
cargo test --workspace -- --nocapture

# no_std check (Cortex-M4F)
cargo check --target thumbv7em-none-eabihf -p vs-types -p vs-crypto -p vs-runtime
```

### Test Requirements

- **New features** must include unit tests and, where applicable, integration tests
- **Bug fixes** must include a regression test
- **Security-critical code** (crypto, key management, authentication) requires:
  - Known-answer test vectors from published standards (NIST, RFC)
  - Error path coverage (invalid inputs, expired keys, revoked keys)
  - Boundary condition tests
- **Target coverage:** 85% for core crates, 70% for domain-specific crates

### Fuzz Testing

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run a fuzz target
cd core
cargo +nightly fuzz run fuzz_can_frame -- -max_total_time=300
```

### Benchmarks

```bash
# Run all benchmarks
cargo bench --workspace

# Specific benchmark
cargo bench --bench cratonshield_benchmarks
```

## Pull Request Process

1. **Ensure CI passes.** All checks must be green before review.
2. **One logical change per PR.** Don't mix features, fixes, and refactors.
3. **Update documentation.** If your change affects behavior, update the relevant docs.
4. **Add tests.** New code must have adequate test coverage.
5. **Fill out the PR template.** Describe what changed, why, and how to test it.
6. **Request review.** At least one maintainer approval is required.

### Review Criteria

Reviewers will check for:

- Correctness and completeness
- `no_std` compatibility
- Security implications (constant-time operations, zeroization, input validation)
- Test coverage
- Documentation quality
- Performance impact (especially for hot-path code in monitors and firewall)

### After Merge

- The maintainer team will handle releases and changelog updates
- Your contribution will be acknowledged in the changelog

## Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.** Instead, follow the [security policy](SECURITY.md) for responsible disclosure.

## License

By contributing to Craton Shield, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE). By signing off your commits, you certify compliance with the Developer Certificate of Origin.
