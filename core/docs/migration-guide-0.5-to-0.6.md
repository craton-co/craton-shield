# Migration Guide: 0.5.x to 0.6.0

> This guide covers breaking changes and migration steps when upgrading from Craton Shield 0.5.x to 0.6.0.

## Breaking Changes

### API Changes

#### vs-crypto: Default RNG now validates output (S1)

`default_rng()` rejects zero-entropy output. Code that previously relied on the (buggy) all-zeros default will now receive an error.

**Before (0.5.x):**
```rust
let rng = default_rng(); // silently returned all zeros
```

**After (0.6.0):**
```rust
let rng = default_rng(); // returns error if entropy source produces zeros
// Handle the error appropriately
```

#### vs-crypto: HSM mock-hsm feature provides full operations (S2)

The `mock-hsm` feature now provides full HMAC-SHA-256 and ECDH P-256 instead of returning `NotInitialized`.

**Before (0.5.x):**
```rust
// mock-hsm operations returned Err(CryptoError::NotInitialized)
let result = hsm.hmac_sha256(key, data); // -> Err(NotInitialized)
```

**After (0.6.0):**
```rust
// mock-hsm operations now succeed with real computations
let result = hsm.hmac_sha256(key, data); // -> Ok(mac)
```

#### vs-key-manager: import_key() no longer discards material (S4)

`import_key()` now correctly stores key material. Code that worked around the silent discard must be reviewed.

**Before (0.5.x):**
```rust
key_manager.import_key(id, material); // material silently discarded
```

**After (0.6.0):**
```rust
key_manager.import_key(id, material); // material stored correctly in KeyStore
```

#### vs-ota-validator: Full TUF delegation chain (S5)

TUF validation now requires timestamp, snapshot, and targets metadata in addition to root. Single-role root-only validation is no longer sufficient.

**Before (0.5.x):**
```rust
// Only root metadata was validated
validator.verify_root(&root_metadata)?;
```

**After (0.6.0):**
```rust
// Full 4-role delegation chain required
validator.verify_root(&root_metadata)?;
verify_timestamp(&timestamp_metadata, &root)?;
verify_snapshot(&snapshot_metadata, &root)?;
verify_targets(&targets_metadata, &root)?;
```

New types to use: `TufTimestamp`, `TufSnapshot`, `TufTargets`, `TufTargetEntry`.

#### vs-ota-validator: JSON parser computes content hash (S6)

`parse_tuf_root_with_hash()` now computes a real SHA-256 content hash instead of returning zeros.

**Before (0.5.x):**
```rust
let (root, hash) = parse_tuf_root_with_hash(json); // hash was all zeros
```

**After (0.6.0):**
```rust
let (root, hash) = parse_tuf_root_with_hash(json); // hash is real SHA-256
```

#### vs-secure-boot: Extended TPM attestation (S7) and boot failure policy (S8)

New PCR functions and policy-aware boot verification replace the simpler attestation API.

**Before (0.5.x):**
```rust
let result = verify_boot_chain(&measurements);
```

**After (0.6.0):**
```rust
use vs_secure_boot::{BootFailurePolicy, BootVerificationOutcome};

// Use policy-aware verification
let outcome = verify_boot_chain_with_policy(&measurements, BootFailurePolicy::Halt)?;

// New PCR operations available
extend_pcr(pcr_index, data)?;
let value = read_pcr(pcr_index)?;
```

#### vs-integrity: Constant-time comparison change (S9)

Custom constant-time comparison replaced with `subtle::ConstantTimeEq`. If you implemented custom comparison logic against the old internal API, update to use `subtle`.

### Configuration Changes

#### TufRoot struct: per-role key fields

`TufRoot` now includes per-role key delegation fields (targets, snapshot, timestamp keys and thresholds). Existing code constructing `TufRoot` must supply the new fields.

**Before (0.5.x):**
```rust
let root = TufRoot {
    version: 1,
    keys: root_keys,
    threshold: 2,
    // ...
};
```

**After (0.6.0):**
```rust
let root = TufRoot {
    version: 1,
    keys: root_keys,
    threshold: 2,
    targets_keys: vec![...],
    targets_threshold: 1,
    snapshot_keys: vec![...],
    snapshot_threshold: 1,
    timestamp_keys: vec![...],
    timestamp_threshold: 1,
    // ...
};
```

### Removed Features

No features were removed in 0.6.0. The UDS diagnostic gateway and QNX HAL stubs were moved to the [auto/](../../auto/) directory in 0.5.0 and remain there.

## Step-by-Step Migration

1. **Update Cargo.toml dependency version**
   ```toml
   [dependencies]
   craton-shield = "0.6.0"
   ```

2. **Fix default RNG usage** -- Handle the error case from `default_rng()` since it now validates entropy output.

3. **Update mock-hsm consumers** -- If your tests expected `Err(NotInitialized)` from mock-hsm operations, update them to expect `Ok(...)` with real cryptographic results.

4. **Fix import_key() call sites** -- Remove any workarounds for the silent-discard bug. Verify that imported key material is used correctly downstream.

5. **Add full TUF metadata** -- Provide timestamp, snapshot, and targets metadata alongside root. Use the new `TufTimestamp`, `TufSnapshot`, `TufTargets` types and standalone verification functions.

6. **Update TufRoot construction** -- Add per-role key delegation fields (targets_keys, snapshot_keys, timestamp_keys and their thresholds).

7. **Update hash expectations** -- If code checked for or ignored zero hashes from `parse_tuf_root_with_hash()`, update to handle real SHA-256 values.

8. **Migrate to policy-aware boot verification** -- Replace `verify_boot_chain()` with `verify_boot_chain_with_policy()` and choose a `BootFailurePolicy`.

9. **Update constant-time comparisons** -- If referencing internal comparison utilities from vs-integrity, switch to `subtle::ConstantTimeEq`.

10. **Run tests to verify** -- `cargo test --workspace` should pass with all 1,194 tests (1,014 unit + 180 integration).

## New Features Available After Migration

- **Post-quantum cryptography (S3)**: ML-KEM-768 and ML-DSA-65 trait definitions and `StubPostQuantumProvider`; concrete software provider via `pq-software` feature.
- **TUF 4-role delegation**: Full timestamp, snapshot, targets verification with cross-reference checks.
- **PCR operations**: `extend_pcr()`, `read_pcr()`, and PCR digest computation for secure boot attestation.
- **Boot failure policies**: `Halt`, `Rollback`, `ReportAndContinue` via `verify_boot_chain_with_policy()`.
- **`find_signed_value()` JSON extractor**: For computing TUF metadata hashes.
- **`PqSoftwareProvider::new_with_keys()`**: Convenience constructor for post-quantum provider.
- **Performance improvements**: Hot-path optimizations across 7 crates (firewall sorted-priority early exit, hash-based rate limiter, ETH hash-indexed allow-list, event logger cached serialization, CAN sorted allowlist, policy engine time validation fast path, anomaly bit-mask indexing).
- **Competitive benchmark suite**: 36 benchmarks covering scaling, crypto baselines, throughput, and framework overhead.
