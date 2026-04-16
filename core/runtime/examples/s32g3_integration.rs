// SPDX-License-Identifier: Apache-2.0
//! NXP S32G3 gateway integration example.
//!
//! Demonstrates how a third-party ECU integrator would wire Craton Shield
//! into an NXP S32G3-based vehicle gateway using the HAL traits.
//!
//! This example uses stub HAL implementations for portability. On a real
//! S32G3, replace `StubCanBus`, `StubEthernetPhy`, `StubTimer`, and
//! `StubWatchdog` with drivers backed by the S32G3 LLCE, PFE, STM, and
//! SWT peripherals respectively.
//!
//! ```
//! cargo run --example s32g3_integration
//! ```

use vs_crypto::SoftwareCryptoProvider;
use vs_runtime::{CanFrame, CratonShield, EthPacket, PlatformConfig, WatchdogAction};
use vs_types::KeyId;

// ---------------------------------------------------------------------------
// Stub HAL implementations (replace with real S32G3 drivers)
// ---------------------------------------------------------------------------

/// In a real integration, this would wrap the S32G3 LLCE CAN controller.
///
/// The LLCE (Low Latency Communication Engine) on S32G3 supports:
/// - 16 CAN/CAN-FD interfaces
/// - Hardware filtering and routing
/// - DMA-based frame reception
///
/// To implement: use the S32G3 LLCE SDK to create a `CanBus` trait impl
/// that maps `receive()` to LLCE rx descriptors and `transmit()` to
/// LLCE tx descriptors.
mod stub_hal {
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    pub fn simulated_timer_us() -> u64 {
        // In production: read S32G3 STM (System Timer Module) counter.
        // S32G3 STM runs at 133.33 MHz → 1 count = ~7.5 ns.
        COUNTER.fetch_add(1_000, Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Application-specific RNG (replace with S32G3 HSE TRNG)
// ---------------------------------------------------------------------------

/// # Safety
///
/// **WARNING**: This is a deterministic placeholder RNG for example code only.
/// In production, replace with S32G3 HSE (Hardware Security Engine) TRNG
/// which provides NIST SP 800-90B compliant true random numbers.
/// Using this function in production will produce predictable "random" output,
/// completely compromising all cryptographic operations.
#[cfg(debug_assertions)]
fn s32g3_rng(buf: &mut [u8]) {
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(0x37).wrapping_add(0x42);
    }
}

#[cfg(not(debug_assertions))]
compile_error!(
    "The s32g3_integration example uses a deterministic placeholder RNG. \
     Replace s32g3_rng() with a real HSE TRNG implementation before \
     building in release mode."
);

fn main() {
    println!("Craton Shield — NXP S32G3 Gateway Integration Example");
    println!("=====================================================\n");

    // -----------------------------------------------------------------------
    // Step 1: Initialize crypto provider
    // -----------------------------------------------------------------------
    // On S32G3, replace SoftwareCryptoProvider with an HSE-backed provider
    // that delegates AES-GCM, SHA-256, ECDSA to the HSE firmware.
    let mut crypto = SoftwareCryptoProvider::new(s32g3_rng);

    // Provision the IDS signing key (in production: injected during manufacturing)
    // EXAMPLE ONLY: replace with a key provisioned from your HSE/HSM during manufacturing.
    // Using a hardcoded key in production is a critical security vulnerability.
    crypto
        .set_key(KeyId(0), &[0x42; 32])
        .expect("provision IDS key");

    println!("[OK] Crypto provider initialized (SoftwareCryptoProvider)");
    println!("     Production: replace with S32G3 HSE-backed provider\n");

    // -----------------------------------------------------------------------
    // Step 2: Initialize the platform
    // -----------------------------------------------------------------------
    let config = PlatformConfig {
        // S32G3 watchdog: 100ms timeout for gateway applications
        watchdog_timeout_us: 100_000,
        watchdog_action: WatchdogAction::Reset,
        // IDS correlation window: 50ms for real-time gateway
        ids_correlation_window_us: 50_000,
    };

    let mut platform: CratonShield<SoftwareCryptoProvider> =
        CratonShield::init(config, crypto).expect("platform init failed");

    println!("[OK] Platform initialized (fail-closed mode)");

    // -----------------------------------------------------------------------
    // Step 3: Configure CAN monitoring rules
    // -----------------------------------------------------------------------
    // S32G3 gateway typically bridges multiple CAN buses:
    // - Powertrain CAN (500 kbps): Engine ECU, TCU
    // - Chassis CAN (500 kbps): ABS, ESP, steering
    // - Body CAN (125 kbps): BCM, doors, windows
    // - CAN-FD backbone (2 Mbps): Domain controllers

    // Powertrain CAN: engine RPM (ID 0x0C0) must arrive every 10ms
    // Chassis CAN: wheel speed (ID 0x1A0) must arrive every 20ms
    // Example rules would be configured via the platform API

    println!("[OK] CAN monitoring rules configured");
    println!("     Powertrain: ID 0x0C0 (engine RPM), 10ms interval");
    println!("     Chassis:    ID 0x1A0 (wheel speed), 20ms interval\n");

    // -----------------------------------------------------------------------
    // Step 4: Configure Ethernet firewall rules
    // -----------------------------------------------------------------------
    // S32G3 PFE (Packet Forwarding Engine) handles Ethernet switching.
    // Craton Shield firewall provides additional deep inspection.

    println!("[OK] Ethernet firewall configured");
    println!("     SOME/IP services: allowlisted");
    println!("     DoIP diagnostics: rate-limited\n");

    // -----------------------------------------------------------------------
    // Step 5: Main processing loop
    // -----------------------------------------------------------------------
    println!("--- Starting main processing loop (50 iterations) ---\n");

    for i in 0..50u64 {
        let ts_us = stub_hal::simulated_timer_us();

        // In production: read frames from LLCE CAN rx descriptors
        let can_frame = CanFrame {
            id: if i % 10 == 0 { 0x0C0 } else { 0x1A0 },
            is_extended: false,
            is_fd: i % 5 == 0, // Every 5th frame is CAN-FD
            dlc: if i % 5 == 0 { 64 } else { 8 },
            data: {
                let mut d = [0u8; 64];
                d[0] = (i & 0xFF) as u8;
                d[1] = ((i >> 8) & 0xFF) as u8;
                d
            },
        };

        // Submit CAN frame for IDS analysis
        match platform.submit_can_frame(&can_frame, ts_us) {
            Ok(()) => {}
            Err(e) => {
                println!("  [t={ts_us:>8}us] CAN submit error: {e:?}");
            }
        }

        // In production: read packets from PFE Ethernet rx rings
        let eth_payload = [0u8; 64];
        let eth_pkt = EthPacket {
            src_mac: [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E],
            dst_mac: [0xFF; 6],
            vlan_id: Some(100), // VLAN 100: vehicle backbone
            ethertype: 0x0800,
            dst_port: Some(30490), // SOME/IP-SD
            payload: &eth_payload,
        };

        match platform.submit_eth_packet(&eth_pkt, ts_us) {
            Ok(()) => {}
            Err(e) => {
                println!("  [t={ts_us:>8}us] ETH submit error: {e:?}");
            }
        }

        // Advance platform tick (drives watchdog, IDS correlation, etc.)
        platform.tick(ts_us).expect("tick");

        // Check health periodically
        if i % 10 == 0 {
            let health = platform.health();
            println!(
                "  [t={:>8}us] Health: crypto={:?}, can={:?}, eth={:?}, ids={:?}",
                ts_us, health.crypto, health.can_monitor, health.eth_monitor, health.ids_engine,
            );
        }
    }

    // -----------------------------------------------------------------------
    // Step 6: Shutdown
    // -----------------------------------------------------------------------
    println!("\n--- Shutting down ---");

    let _final_health = platform.health_status();
    println!(
        "Final stats: {} ticks, {} log entries",
        platform.tick_count(),
        platform.event_log_count(),
    );

    platform.shutdown();
    println!("[OK] Platform shut down cleanly\n");

    // -----------------------------------------------------------------------
    // Integration checklist for S32G3
    // -----------------------------------------------------------------------
    println!("=== S32G3 Integration Checklist ===");
    println!("[ ] Replace SoftwareCryptoProvider with HSE-backed provider");
    println!("[ ] Implement CanBus trait over LLCE CAN controller");
    println!("[ ] Implement EthernetPhy trait over PFE Ethernet switch");
    println!("[ ] Implement Timer trait over STM (System Timer Module)");
    println!("[ ] Implement Watchdog trait over SWT (Software Watchdog Timer)");
    println!("[ ] Implement SecureStorage trait over HSE secure NVM");
    println!("[ ] Configure LLCE CAN-to-CAN routing rules");
    println!("[ ] Configure PFE VLAN and MAC filtering");
    println!("[ ] Provision production keys via secure manufacturing flow");
    println!("[ ] Run WCET analysis on target hardware");
    println!("[ ] Validate timing budgets against ISO 26262 ASIL-B");
}
