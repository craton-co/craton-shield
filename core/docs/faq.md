# Frequently Asked Questions

> Craton Shield 0.7.0

## Security

### How do I report a security vulnerability?

See [SECURITY.md](../../SECURITY.md) for our responsible disclosure policy.
Do not open a public issue for security vulnerabilities.

## General

### What is the difference between Craton Shield Core and Craton Shield Platform?

**Core** (this repository) provides open-source detection traits, monitoring
logic, event logging, mock crypto for testing, and HAL abstractions.
The **[auto/](../../auto/)** directory adds automotive-specific crates (signal-ids,
diag-gateway, v2x, autosar, hal-qnx, vsoc-telemetry). The **[industrial/](../../industrial/)**
directory adds industrial control system crates, and the **[embedded/](../../embedded/)**
directory adds embedded IoT crates. **Platform** (enterprise) adds production-grade
HSM drivers and commercial support.

### Does Craton Shield require `std`?

No. All crates except `vs-hal-linux` and `vs-storage` (with `std` feature) are
`#![no_std]` with zero heap allocations. This makes Craton Shield suitable for
bare-metal Cortex-M, RTOS, and Linux targets.

### What Rust version do I need?

The minimum supported Rust version (MSRV) is **1.82**. This is tested in CI.
See [api-stability.md](api-stability.md) for MSRV bump policy.

## Integration

### How do I port Craton Shield to a new MCU?

See the [Porting Guide](porting-guide.md). You need to implement four HAL
traits: `Timer`, `CanBus`, `EthernetPhy`, and optionally `HsmHardware`.
Start with `Timer` (simplest) and work up.

### Can I use Craton Shield without CAN?

Yes. `CratonShield::init()` initializes all subsystems, but you only need to
call the `submit_*` methods for buses you have. Unused monitors stay idle with
no overhead.

### How do I configure detection thresholds?

Add `CanRule` entries to the `CanMonitor` for CAN detection thresholds (flood
rate, max DLC, allowlist). For Ethernet, configure `EthMonitorConfig`. For the
firewall, add `FirewallRule` entries. See the [Safety Manual](safety-manual.md)
for recommended defaults and ranges.

### What is the memory footprint?

Typical embedded footprint is **256-512 KB** Flash depending on features
enabled. RAM usage depends on capacity tier:

| Tier | Firewall rules | Event log | Storage entries |
|:-----|---------------:|----------:|----------------:|
| Base | 128 | 256 | 64 |
| `capacity-large` | 256 | 512 | 128 |
| `capacity-xl` | 512 | 1024 | 256 |

### What are the minimum stack size requirements?

The `CratonShield` runtime struct and its subsystems are allocated on the stack.
Approximate stack requirements by capacity tier:

| Tier | Approximate stack usage |
|:-----|------------------------:|
| Base | ~80 KB |
| `capacity-large` | ~120 KB |
| `capacity-xl` | ~200 KB |

On embedded targets with limited stack space, ensure your linker script
allocates sufficient stack. The largest contributors are `EventLog` (~54 KB
at base tier), `CanMonitor` (~30 KB), and `Firewall` (~16 KB at base tier).

### How do I integrate with C/C++ code?

Use the `vs-ffi` crate which exposes a C ABI via `include/cratonshield.h`.
See the [Safety Manual](safety-manual.md) section on C FFI integration for the
initialization sequence and threading requirements.

## Testing

### How do I run the full test suite?

```bash
cargo test --workspace
```

For Linux HAL tests with virtual CAN:

```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
cargo test -p vs-hal-linux
```

### How do I run benchmarks?

```bash
cargo bench --bench cratonshield_benchmarks
```

For WCET analysis:

```bash
cargo build --bin wcet-harness --features wcet --release
./target/release/wcet-harness
```

## Troubleshooting

### `cargo check` fails on `thumbv7em-none-eabihf`

Ensure you have the target installed:

```bash
rustup target add thumbv7em-none-eabihf
```

Only the `no_std` crates compile for this target. Use `-p` to select specific
crates (see CI configuration for the list).

### Tests fail with "vcan0: No such device"

The `vs-hal-linux` tests require a virtual CAN interface. Set it up with:

```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

### `cargo audit` reports a vulnerability

Check if the advisory affects Craton Shield's usage. Our policy is to patch
within 72 hours for security-critical dependencies. File an issue if you
find a dependency vulnerability we haven't addressed.

### Cross-compilation fails for aarch64

Install the cross-compilation toolchain:

```bash
sudo apt-get install gcc-aarch64-linux-gnu libc6-dev-arm64-cross
```

Or use QEMU user-mode emulation (as CI does):

```bash
sudo apt-get install qemu-user qemu-user-binfmt
cargo test --workspace --target aarch64-unknown-linux-gnu
```
