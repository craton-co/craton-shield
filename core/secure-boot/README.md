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
- `BootStage` — boot chain stage (`Bootloader`, `Hypervisor`, `Os`, `Application(n)`)
- `BootAttestation` — result containing PCR snapshot, chain hash, and timestamp
- `BootFailurePolicy` — failure response policy (`Halt`, `ReportOnly`, `RequestRollback`)
- `TpmAttestation` — trait for TPM quote generation and PCR operations
- `SoftwareTpm` — pure-software `TpmAttestation` (test / dev only, **feature-gated** behind `software-tpm`)
- `HardwareTpm` — `TpmAttestation` backed by a `CryptoProvider` (no real TPM 2.0 wire protocol; see below)

## Software-vs-Hardware Roots of Trust

`Craton Shield` v0.7 ships **two software-backed** `TpmAttestation`
implementations. **Neither is a real TPM 2.0 device.** Both produce
quotes that are useful for unit tests, simulation, and platforms
without a discrete TPM, but **only a real TPM 2.0 chip provides a
hardware root of trust.**

| Type           | Availability                                  | Crypto backend          | Quote shape                             | Hardware root of trust? |
| -------------- | --------------------------------------------- | ----------------------- | --------------------------------------- | ----------------------- |
| `SoftwareTpm`  | feature-gated: `--features software-tpm`      | In-process HMAC/SHA-256 | Dual-HMAC over PCR digest \|\| nonce    | No                      |
| `HardwareTpm`  | always available                              | `CryptoProvider` trait  | Dual-HMAC over PCR digest \|\| nonce    | No (still software)     |
| *(future)* real TPM 2.0 transport | planned v1.0              | Discrete TPM chip       | `TPMS_ATTEST` signed by RSASSA / ECDSA  | **Yes** (planned v1.0)  |

Although the `CryptoProvider` trait wired into `HardwareTpm` *can*
delegate to a secure element in production, the type itself does
**not** speak the TPM 2.0 wire protocol (TIS / CRB), does **not** emit
a `TPMS_ATTEST` structure, and its signature is a custom
dual-HMAC-SHA-256 construction rather than a TPM2-defined signature
scheme. Treat the name as "crypto-provider-backed", not as a hardware
guarantee.

### Forward-looking: `vs_hal::Tpm2Transport`

A placeholder trait `Tpm2Transport` has been added to `core/hal` under
the `tpm2-experimental` cargo feature. It documents the intended
transport-level surface for a real TPM 2.0 device (TIS or CRB over
SPI / LPC / I2C, targeting parts such as Infineon SLB 9670/9672, ST
ST33TPHF, or Nuvoton NPCT75x). The trait is annotated `#[deprecated]`
to discourage accidental production use — **the API is not finalized
and will change before v1.0.** Downstream consumers wishing to
prototype a true hardware path may implement it, but should expect
breaking changes.

### v1.0 commitment

Before tagging `1.0.0`, `Craton Shield` will:

1. Finalize the `Tpm2Transport` API (or replace it with a stable
   successor) and remove the `#[deprecated]` annotation.
2. Ship a reference `Tpm2Transport` implementation against a discrete
   TPM 2.0 chip behind an opt-in feature.
3. Provide a `Tpm2Tpm` (working name) implementation of
   `TpmAttestation` that produces real `TPMS_ATTEST`-shaped quotes,
   signed by the TPM's attestation key, so that `BootVerifier`
   consumers can opt into a hardware root of trust.

Until then, treat all `TpmAttestation` implementations shipped from
this crate as **software-only** primitives.

## Usage

```rust,ignore
use vs_crypto::{CryptoProvider, KeyId};
use vs_secure_boot::{BootEntry, BootFailurePolicy, BootStage, BootVerifier};

fn verify<C: CryptoProvider>(
    crypto: C,
    pub_key: &[u8; 65],
    boot_entries: &[BootEntry],
    timestamp_us: u64,
) -> Result<(), vs_types::VsError> {
    let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);
    verifier.register_pub_key(KeyId(0), pub_key)?;

    let attestation = verifier.verify_boot_chain(boot_entries, timestamp_us)?;
    let _ = attestation.chain_hash;
    Ok(())
}
```

The chain MUST begin at `BootStage::Bootloader` and stages MUST be
contiguous (no skipping `Hypervisor` or `Os`). Non-contiguous chains
are rejected with `VsError::PolicyViolation`.

## Feature Flags

- `software-tpm` — enable the `SoftwareTpm` type. Rejected by a
  `compile_error!` in release builds (`not(debug_assertions)` and
  `not(test)`); it remains available in debug and test builds. Intended
  for tests and simulation only.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
