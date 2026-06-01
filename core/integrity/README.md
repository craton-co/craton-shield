# vs-integrity

Memory region integrity monitoring with constant-time SHA-256 verification.

## Overview

This crate monitors memory regions for unauthorized modifications by
periodically computing SHA-256 hashes and comparing them against expected
values using constant-time comparison (via the `subtle` crate). It supports
up to 64 concurrently monitored regions with slot reuse, per-region tamper
status, HMAC-authenticated baseline updates, tamper callbacks, epoch-based
freshness tracking, and snapshot/restore for persistence across reboots.

## Key Types

- `IntegrityMonitor<C>` — monitors registered memory regions for hash mismatches
- `RegionInfo` — public view of region metadata (does not expose the expected hash)
- `IntegrityResult` — per-region check result with region ID and status
- `IntegrityStatus` — check outcome (`Ok`, `Tampered`, `Unavailable`)
- `MonitorSnapshot` — opaque, `#[repr(C)]` snapshot for persistence
- `TamperCallback` — function pointer invoked on tamper detection

## Usage

```rust,ignore
use vs_integrity::{IntegrityMonitor, IntegrityResult, IntegrityStatus, build_update_auth_message};

// Create a monitor with your CryptoProvider.
let mut monitor = IntegrityMonitor::new(crypto);

// Register a memory region (computes baseline hash automatically).
monitor.register_region(1, 0x2000_0000, &firmware_data)?;

// Verify a single region (base_addr must match registration).
let result = monitor.verify_region(1, 0x2000_0000, &current_data)?;
assert_eq!(result.status, IntegrityStatus::Ok);

// Verify all regions at once (fixed-size buffer for no_std).
let mut results = [IntegrityResult { region_id: 0, status: IntegrityStatus::Ok }; 64];
let count = monitor.verify_all(
    |id, addr, len| read_memory(addr, len),
    &mut results,
)?;

// Authenticated baseline update (requires set_auth_key).
monitor.set_auth_key(hmac_key_id);
let msg = build_update_auth_message(&crypto, 1, &new_data)?;
let tag = compute_hmac(hmac_key_id, &msg); // via your CryptoProvider
monitor.update_baseline(1, &new_data, Some(&tag))?;

// Tick-based periodic checks.
monitor.set_check_interval(100);
loop {
    if monitor.tick() {
        monitor.verify_all(data_provider, &mut results)?;
    }
}
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
