# Core Examples

Runnable examples demonstrating Craton Shield core functionality.

## Examples

| Example | Language | Description | How to Run |
|:--------|:---------|:------------|:-----------|
| `basic_ids.rs` | Rust | CAN monitor setup with detection rules, frame processing, and alert routing through the IDS engine | `cargo run --example basic_ids` |
| `encrypted_storage.rs` | Rust | Transparent AES-GCM encrypted storage with tamper detection and nonce management | `cargo run --example encrypted_storage --features "mock-hsm"` |
| `eth_monitoring.rs` | Rust | Ethernet monitor for SOME/IP allowlisting, ARP anomaly detection, and VLAN filtering | `cargo run --example eth_monitoring` |
| `ffi_example.c` | C | Full lifecycle of the C FFI interface: init, CAN/ETH submission, tick loop, health query, shutdown | See build instructions in file header |
| `firewall_policy.rs` | Rust | Network firewall rule configuration and XACML-lite policy engine for access control decisions | `cargo run --example firewall_policy` |
| `s32g3_integration.rs` | Rust | NXP S32G3 gateway integration pattern with stub HAL implementations and integration checklist | `cargo run --example s32g3_integration` |

## Prerequisites

- Rust 1.82+ (stable)
- For `encrypted_storage`: the `mock-hsm` feature flag (never use in production)
- For `ffi_example.c`: build the `vs-ffi` shared library first, then compile and link with a C compiler (see file header for detailed instructions)

## Notes

- All Rust examples run on the host (x86_64 or aarch64) and do not require embedded hardware.
- The `s32g3_integration` example uses stub HAL implementations. Replace them with real S32G3 peripheral drivers for production use.
- See [integration-examples.md](../docs/integration-examples.md) for additional third-party middleware integration patterns (AUTOSAR, SOME/IP, UDS, OTA).

## License

Apache-2.0. See [LICENSE](../../LICENSE).
