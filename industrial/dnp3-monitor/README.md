# vs-dnp3-monitor

DNP3 intrusion detection for Craton Shield (IEC 62443).

## Overview

Monitors DNP3 traffic for security anomalies in industrial
control systems. Designed for industrial gateways and PLCs.

**MSRV:** 1.82 | **Environment:** `#![no_std]`, zero heap allocation

## Features

- **Function code allowlist** — bitmask-based allowlist for FCs 0-31; FCs >= 32 are blocked except for response codes 129 (RESPONSE) and 130 (UNSOLICITED_RESPONSE), which are required by the protocol for outstation-to-master traffic
- **Address validation** — source/destination address filtering with wildcard support
- **Write protection** — block write operations on read-only address rules
- **Application-layer sequence validation** — 4-bit forward-progress window detects replays and duplicates
- **Link-layer CRC verification** (IEEE 1815 §9.2.2.4) — `verify_crc()` validates the per-block CRC-16/DNP3; mismatches raise `BadLinkCrc` (High). **Disabled by default in 0.7.0** — see WARNING below
- **Transport-layer sequence tracking** (IEEE 1815 §8.2) — per-link 6-bit transport SEQ window; out-of-order frames raise `TransportSeqAnomaly`
- **DNP3-SA downgrade detection (heuristic)** — FC 32/33 frames whose payload contains zero bytes at the candidate algorithm-code offsets raise `SaDowngrade` (High). This is a coarse heuristic and may produce false positives; see the doc-comment on `sa_proposes_weak_algorithm`
- **IIN flag spoofing** — tracks response IIN1 `LOCAL_CONTROL` and `DEVICE_TROUBLE` bits; rising-edge `LOCAL_CONTROL` and `DEVICE_TROUBLE` flapping raise `IinFlagSpoofing`

## ⚠️ Link-layer CRC: disabled by default in 0.7.0

`Dnp3Frame` (defined in `vs-types-ind`) does not retain the raw `length`
(byte 2) and `control` (byte 3) bytes of the link header. Per
IEEE 1815-2012 §9.2.2.4 those bytes are part of the CRC input, so the
monitor's reconstruction of the header from `Dnp3Frame` alone is lossy
and the computed CRC almost never matches the wire value on real
traffic. To avoid generating near-100% false positives, link-layer CRC
validation is **disabled by default** in this release.

Enable it only when your transport / parser has already validated the
CRC at a lower layer (and clears `link_crc_provided`), or use one of the
toggle setters listed below to opt in once your data path is known
correct.

## Stack Budget

~500 bytes

## Usage

```rust
use vs_dnp3_monitor::Dnp3Monitor;
use vs_types_ind::Dnp3Frame;

let mut monitor = Dnp3Monitor::new();

// Allow src=1 -> dst=10, FCs 0-3 enabled (mask 0x0F), read-only, no rate cap
monitor.add_address_rule(1, 10, 0x0000_000F, true, 0).unwrap();

// Inspect a frame
let result = monitor.inspect(&frame);
if !result.allowed {
    // frame was blocked
}
```

## Detector toggles

All toggles are `&mut self` setters that enable/disable individual
detectors at runtime. Defaults are noted in parentheses.

- `set_link_crc_validation(enabled: bool)` — link-layer CRC verification
  (default: **disabled**; see WARNING above). Alias:
  `set_crc_validation_enabled`.
- `set_transport_seq_validation(enabled: bool)` — transport-layer 6-bit
  SEQ tracking (default: enabled).
- `set_sa_downgrade_detection(enabled: bool)` — DNP3-SA heuristic
  downgrade detector for FC 32 / 33 (default: enabled).
- `set_iin_detection(enabled: bool)` — IIN1 flag spoofing detector on
  response frames (default: enabled).
- `set_seq_validation(enabled: bool)` — application-layer 4-bit SEQ
  replay detector (default: enabled).

Example:

```rust
let mut monitor = Dnp3Monitor::new();
// Opt into CRC validation only after confirming the upstream parser
// retains the full link header.
monitor.set_link_crc_validation(true);
// Disable the SA downgrade heuristic if it is too noisy on your link.
monitor.set_sa_downgrade_detection(false);
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
