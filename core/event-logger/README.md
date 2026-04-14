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

```rust
use vs_event_logger::{EventLog, EventType};

let mut log = EventLog::<_, 1024>::new(crypto, hmac_key_id);
log.append(EventType::SecurityAlert, &payload, timestamp_us)?;
let integrity = log.verify_chain()?;
assert!(integrity.first_tampered_seq.is_none());
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
