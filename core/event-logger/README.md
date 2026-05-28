# vs-event-logger

Tamper-evident HMAC-chained event logging ring buffer.

## Overview

This crate provides a fixed-capacity ring buffer for security event logging.
Each entry is chained to the previous via HMAC-SHA256, creating a
tamper-evident log that can detect deletion or modification of any entry.
The chain integrity can be verified at any time to detect log tampering.

## Key Types

- `EventLog<C, CAPACITY>` — HMAC-chained ring buffer of log entries
- `LogEntry` — a single log entry with sequence, timestamp, event type, payload, and HMAC
- `EventType` — event categories (SecurityAlert, KeyOperation, BootEvent, DiagnosticSession, etc.)
- `ChainIntegrity` — result of chain verification with count and first-tampered sequence

## Usage

```rust,ignore
use vs_event_logger::{EventLog, EventType};
use vs_crypto::CryptoProvider;
use vs_types::{KeyId, VsError};

# fn example<C: CryptoProvider>(crypto: &C, hmac_key_id: KeyId)
#     -> Result<(), VsError>
# {
let payload: &[u8] = &[0xAA; 16];
let timestamp_us: u64 = 1_000;

let mut log = EventLog::<C, 1024>::new(hmac_key_id, crypto)?;
log.append(EventType::SecurityAlert, payload, timestamp_us, crypto)?;
let integrity = log.verify_chain(crypto)?;
assert!(integrity.first_tampered_seq.is_none());
# Ok(())
# }
```

> Note: `verify_chain` only detects in-RAM tampering. After a reboot the log
> resets to sequence 0 with no persistent anchor. If you need cross-reboot
> tamper detection, persist the last sequence number and last entry hash via
> `vs-storage` and re-anchor on boot.

## License

Apache-2.0. See [LICENSE](LICENSE).
