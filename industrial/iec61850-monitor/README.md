# vs-iec61850-monitor

IEC 61850 MMS / GOOSE / SV anomaly detection for Craton Shield (IEC 62443).

## Overview

Monitors IEC 61850 traffic (MMS, GOOSE, and Sampled Values protocols) for
behavioural anomalies in substation automation systems. Designed for IEDs,
gateways, and merging units.

**MSRV:** 1.82 | **Environment:** `#![no_std]`, zero heap allocation

## Security model

**This crate does NOT implement IEC 62351-6 GOOSE/SV authentication.
There is no HMAC verification, no signing, and no cryptographic trust
root.** Frames are accepted on the wire as-is; the monitor only inspects
their plaintext fields.

Detection is **heuristic**, based on:

- `src_mac` of the publishing Ethernet frame,
- `stNum` / `sqNum` counters and baseline-no-downgrade rules,
- timing windows (retransmission decay, `t`-field monotonicity),
- per-publisher bindings learned from configuration or observation.

An attacker who can replicate a legitimate publisher's `src_mac` and
increment the `stNum` / `sqNum` counters correctly **cannot be detected
by this crate**. Layer-2 MAC spoofing on a shared substation LAN is
trivial for any attacker with bus access. **Treat alerts as forensic /
anomaly signals, not as authenticated rejection** of a cryptographically
untrusted peer.

For production-grade authentication, consult **IEC 62351-6:2020** (cyber
security for IEC 61850 GOOSE and Sampled Values) and provide a
HMAC / signature-verifying layer below or alongside this monitor.

## Features

### MMS (Manufacturing Message Specification)

- **Service-type allowlist** -- bitmask filter for MMS confirmed service types
- **Write protection** -- block Write, Define/Delete operations
- **Rate limiting** -- per-invoke-ID token buckets
- **Control-block reservation tracking** -- observe `SelectControl` and
  `CancelControl` operations and remember which client owns each GoCB /
  SvCB. Subsequent GOOSE / SV traffic addressing a reserved control block
  from a different publisher MAC is flagged as `AlertCode::CbHijack`
  (heuristic hijack indicator; not authenticated rejection).

### GOOSE (Generic Object Oriented Substation Event)

- **Publisher allowlist** -- restrict allowed (src_mac, GoCBRef) pairs
  (note: `src_mac` is trivially forgeable; see Security model above)
- **Replay detection** -- stNum/sqNum tracking with baseline no-downgrade
- **Test-flag blocking** -- optionally block test frames
- **Retransmission interval validation** -- IEC 61850-8-1 mandates a
  decay schedule (T0, T1=T0*2, T2=T1*2, ..., T_max). Frames arriving with
  intervals that materially deviate from the published schedule are flagged
  as `AlertCode::RetransmissionAnomaly`.
- **Heuristic time-sync spoofing indicators** -- backwards `t` field or
  implausibly large forward jumps flag `AlertCode::TimeSyncSpoofing`.

### SV (Sampled Values, IEC 61850-9-2)

- **Raw-frame parsing** -- `parse_sv()` decodes a wire buffer
  (EtherType `0x88BA`, post-VLAN-strip).
- **smpCnt monotonicity** -- backwards step or duplicate flagged as
  `AlertCode::SvReplay` (modulo-65536 wrap-around is correctly accepted).
- **Sample-rate anomaly** -- excessive smpCnt gaps and mismatched
  `smpRate` flag `AlertCode::SvRateAnomaly`.
- **IED binding** -- `svID` registered to a fixed publisher MAC; mismatch
  flags `AlertCode::IedMismatch` (heuristic; defeated by MAC spoofing).
- **Heuristic time-sync spoofing indicators** -- shared per-IED tracker
  with GOOSE.

## Stack Budget

~3 KiB.

## Usage

```rust
use vs_iec61850_monitor::{
    Iec61850Monitor, MmsFrame, MmsServiceType, GooseFrame, RetxSchedule,
};
use vs_types_ind::SvFrame;

let mut monitor = Iec61850Monitor::new_strict();

// Configure MMS: read-only, allow Read and GetNameList
let mask = (1u16 << MmsServiceType::Read as u8)
    | (1u16 << MmsServiceType::GetNameList as u8);
monitor.set_mms_service_mask(mask);
monitor.set_mms_read_only(true);

// Configure GOOSE: allow a specific publisher
monitor
    .add_goose_publisher([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], b"")
    .unwrap();

// Configure retransmission schedule and time-sync detection
monitor.set_retx_schedule(RetxSchedule::default_8_1(), true);
monitor.set_time_max_forward_jump_s(60);

// Bind an SV publisher MAC to an svID
monitor
    .add_sv_publisher([0x00, 0x11, 0x22, 0x33, 0x44, 0x66], b"MU1", 80)
    .unwrap();
monitor.set_sv_max_smp_cnt_gap(256);

// Parse a raw SV Ethernet payload and inspect it.
let bytes: &[u8] = &[];
if let Ok(sv) = Iec61850Monitor::parse_sv(bytes, 0) {
    let _ = monitor.inspect_sv(&sv);
}
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
