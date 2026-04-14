# vs-secure-boot

Secure boot chain verification with PCR measurement for Craton Shield.

## Overview

This crate verifies the integrity of the boot chain from bootloader through
hypervisor, OS, and application stages. Each stage's image hash and signature
are validated, and measurements are extended into software PCR registers
to produce a boot attestation snapshot.

## Key Types

- `BootVerifier<C>` — verifies a chain of boot entries and produces attestation snapshots
- `BootEntry` — a single boot stage with image hash, signature, and signer key ID
- `BootStage` — boot chain stage (Bootloader, Hypervisor, Os, Application)
- `BootAttestation` — result containing PCR snapshot, chain hash, and timestamp
- `BootFailurePolicy` — failure response policy (Halt, ReportOnly, RequestRollback)
- `TpmAttestation` — trait for TPM quote generation and PCR operations

## Usage

```rust
use vs_secure_boot::{BootVerifier, BootEntry, BootStage, BootFailurePolicy};

let verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);
let attestation = verifier.verify_chain(&boot_entries, timestamp_us)?;
```

## Feature Flags

See [docs/feature-flags.md](../../docs/feature-flags.md) for the full workspace feature reference.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
