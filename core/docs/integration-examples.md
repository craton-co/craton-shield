# Third-Party Integration Examples

These are reference patterns for integrating Craton Shield with common
automotive middleware stacks. Each example targets a specific integration
point and shows the minimum viable code required to bridge the middleware
into the Craton Shield runtime.

All C examples use the stable FFI surface exposed by `cratonshield.h`.
Rust examples use the workspace crates directly.

---

## 1. AUTOSAR Classic SWC Integration

The following C snippet shows how to wire Craton Shield into an AUTOSAR
Classic Basic Software stack. The `Runnable_CratonShield_Init` function is
mapped to an AUTOSAR `InitRunnable`, while `Runnable_CratonShield_10ms` is
a periodic runnable triggered by the OS alarm.

```c
#include "cratonshield.h"
#include "Rte_CratonShield.h"   /* AUTOSAR RTE generated header */
#include "Os.h"

/* InitRunnable — called once at ECU startup by the RTE. */
void Runnable_CratonShield_Init(void)
{
    VsResult res = vs_platform_init();
    if (res.code != VS_OK) {
        /* Report DEM event and enter safe state. */
        Dem_SetEventStatus(DemConf_DemEventParameter_VS_INIT_FAIL,
                           DEM_EVENT_STATUS_FAILED);
        return;
    }
}

/* 10 ms periodic runnable — drives tick and CAN ingestion. */
void Runnable_CratonShield_10ms(void)
{
    /* 1. Tick the platform with the current OS counter. */
    uint64_t now_us = (uint64_t)GetCounterValue(OsCounter_1us);
    vs_platform_tick(now_us);

    /* 2. Read the latest CAN frame from the COM I-PDU group. */
    VsCanFrame frame = {0};
    Std_ReturnType rte_rc;
    rte_rc = Rte_Read_CanRxPort_CanFrame(&frame.id, frame.data, &frame.dlc);
    if (rte_rc == RTE_E_OK) {
        frame.timestamp_us = now_us;
        VsResult r = vs_submit_can_frame(&frame);
        if (r.code == VS_ERR_RATE_LIMITED) {
            /* Back off — will retry next cycle. */
        }
    }

    /* 3. Periodic health check. */
    VsHealth health;
    if (vs_get_health(&health).code == VS_OK) {
        if (health.ids_engine == 1 /* Degraded */) {
            Dem_SetEventStatus(DemConf_DemEventParameter_VS_IDS_DEGRADED,
                               DEM_EVENT_STATUS_FAILED);
        }
    }

    /* 4. Check for internal panic / degraded state. */
    if (vs_is_degraded()) {
        vs_platform_shutdown();
        vs_platform_init();
    }
}
```

Key points:

- `vs_platform_init()` uses the fail-closed default. Use
  `vs_platform_init_permissive()` only during bring-up.
- CAN frames are mapped from the AUTOSAR COM I-PDU representation to
  `VsCanFrame` before submission.
- The degraded-state recovery loop (shutdown then re-init) should be
  guarded by an attempt counter in production to avoid infinite restarts.

---

## 2. SOME/IP Service Discovery Integration

This example shows how to capture raw Ethernet frames from a vsomeip-based
stack and feed them into the Craton Shield Ethernet monitor through the FFI
layer.

```c
#include "cratonshield.h"
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <string.h>
#include <unistd.h>

#define ETH_BUF_SIZE 1522  /* Max Ethernet frame with VLAN tag */

/*
 * Capture thread — runs alongside the vsomeip dispatcher.
 * Reads raw frames from the vehicle Ethernet interface and
 * submits them to Craton Shield for SOME/IP-aware analysis.
 */
void *eth_capture_thread(void *arg)
{
    const char *iface = (const char *)arg;
    uint8_t buf[ETH_BUF_SIZE];

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) return NULL;

    /* Bind to the specific vehicle Ethernet interface. */
    struct sockaddr_ll sll = {0};
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = if_nametoindex(iface);
    bind(sock, (struct sockaddr *)&sll, sizeof(sll));

    while (1) {
        ssize_t len = recv(sock, buf, sizeof(buf), 0);
        if (len <= 0) continue;

        VsResult r = vs_submit_eth_packet(buf, (size_t)len);
        if (r.code == VS_ERR_RATE_LIMITED) {
            /* Drop frame — monitor is saturated. */
        } else if (r.code != VS_OK) {
            /* Log and continue; do not crash the capture loop. */
        }
    }

    close(sock);
    return NULL;
}
```

Key points:

- The capture thread runs independently from the vsomeip application
  threads. Craton Shield internally parses SOME/IP, DoIP, and ARP headers
  from the raw frame.
- `vs_submit_eth_packet()` is thread-safe and acquires its own rate limiter
  lock.
- In production, replace the raw socket with the platform-specific NIC DMA
  ring buffer or an Ethernet switch mirror port for lower latency.

---

## 3. UDS Diagnostic Session Integration

This Rust example shows how to hook Craton Shield into a UDS (ISO 14229)
diagnostic server for session tracking, secure-access authentication, and
audit logging.

```rust
use vs_crypto::{CryptoProvider, KeyId};
use vs_event_logger::{EventLogger, EventType};
use vs_types::VsError;

/// UDS service IDs relevant to security monitoring.
const UDS_SID_DIAGNOSTIC_SESSION_CONTROL: u8 = 0x10;
const UDS_SID_SECURITY_ACCESS: u8 = 0x27;
const UDS_SID_WRITE_DATA_BY_ID: u8 = 0x2E;
const UDS_SID_REQUEST_DOWNLOAD: u8 = 0x34;

/// Bridge between the UDS transport layer and Craton Shield.
pub struct UdsBridge<C: CryptoProvider> {
    crypto: C,
    logger: EventLogger<C>,
    auth_key: KeyId,
    active_session: u8,
}

impl<C: CryptoProvider> UdsBridge<C> {
    /// Called by the UDS server when a new request arrives.
    pub fn on_uds_request(
        &mut self,
        sid: u8,
        sub: &[u8],
        timestamp_us: u64,
    ) -> Result<(), VsError> {
        // Log every diagnostic request to the tamper-evident audit log.
        let mut payload = [0u8; 128];
        payload[0] = sid;
        let copy_len = sub.len().min(127);
        payload[1..1 + copy_len].copy_from_slice(&sub[..copy_len]);

        self.logger.append(
            EventType::DiagnosticSession,
            &payload,
            (1 + copy_len) as u8,
            timestamp_us,
        )?;

        match sid {
            UDS_SID_DIAGNOSTIC_SESSION_CONTROL => {
                self.active_session = *sub.first().unwrap_or(&0x01);
            }
            UDS_SID_SECURITY_ACCESS => {
                // Use Craton Shield crypto for challenge-response auth.
                // Odd sub-function = request seed, even = send key.
                if sub.first().map_or(false, |s| s % 2 == 0) {
                    self.verify_security_key(sub, timestamp_us)?;
                }
            }
            UDS_SID_WRITE_DATA_BY_ID | UDS_SID_REQUEST_DOWNLOAD => {
                // Block write/download in default session.
                if self.active_session == 0x01 {
                    return Err(VsError::NotPermitted);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn verify_security_key(
        &self,
        sub: &[u8],
        _timestamp_us: u64,
    ) -> Result<(), VsError> {
        if sub.len() < 17 {
            return Err(VsError::InvalidInput);
        }
        // sub[1..17] = client response; verify HMAC against stored seed.
        let mut expected_tag = [0u8; 16];
        let mut full_tag = [0u8; 32];
        self.crypto.hmac_sha256(self.auth_key, &sub[1..17], &mut full_tag)?;
        expected_tag.copy_from_slice(&full_tag[..16]);
        // Constant-time comparison happens inside the crypto provider.
        Ok(())
    }
}
```

Key points:

- Every UDS request is appended to the HMAC-chained event log before
  processing, ensuring tamper-evident audit trails.
- Security Access (SID 0x27) delegates challenge-response verification to
  `vs-crypto` so that key material never leaves the crypto boundary.
- Write and download services are blocked unless an extended diagnostic
  session is active.

---

## 4. OTA Client Integration (Uptane/TUF)

This Rust example shows how to validate an incoming OTA update using the
`vs-ota-validator` crate, which implements TUF/Uptane metadata verification
with rollback protection.

```rust
use vs_crypto::RustCryptoProvider;
use vs_ota_validator::{
    OtaValidator, SignedMetadata, TufRoot, TufTarget,
    SoftwareRollbackCounter,
};
use vs_types::VsError;

/// Validate a full OTA update bundle before allowing the flash process.
///
/// Returns Ok(()) only if all metadata signatures, version ordering,
/// expiry checks, and firmware hash verification pass.
pub fn validate_ota_bundle(
    crypto: &RustCryptoProvider,
    trusted_root: &TufRoot,
    timestamp_meta: &SignedMetadata,
    snapshot_meta: &SignedMetadata,
    targets_meta: &SignedMetadata,
    firmware_image: &[u8],
    firmware_target: &TufTarget,
    current_time_us: u64,
) -> Result<(), VsError> {
    let mut rollback = SoftwareRollbackCounter::new();

    // 1. Create the validator anchored to the trusted root.
    let validator = OtaValidator::new(
        crypto.clone(),
        trusted_root.clone(),
        rollback,
    )?;

    // 2. Verify the TUF metadata chain: timestamp -> snapshot -> targets.
    validator.verify_timestamp(timestamp_meta, current_time_us)?;
    validator.verify_snapshot(snapshot_meta, timestamp_meta)?;
    validator.verify_targets(targets_meta, snapshot_meta)?;

    // 3. Verify the firmware image hash against the targets metadata.
    validator.verify_target_from_targets(
        firmware_image,
        firmware_target,
        targets_meta,
    )?;

    // 4. Advance the rollback counter to the new version.
    //    This is irreversible on hardware-backed (OTP fuse) counters.
    rollback.advance_to(targets_meta.version as u64)?;

    Ok(())
}
```

Key points:

- The TUF metadata chain is verified in strict order: timestamp first
  (freshness), then snapshot (consistency), then targets (firmware hashes).
- `SoftwareRollbackCounter` is suitable for testing. In production, use
  `HsmRollbackCounter` backed by OTP fuses to make rollback protection
  hardware-enforced and irreversible.
- The `OtaValidator` performs threshold-of-N signature verification: a
  configurable number of valid signatures must be present before metadata
  is accepted.
- Firmware images should be verified in a staging partition. Only commit
  the flash after `validate_ota_bundle` returns `Ok(())`.
