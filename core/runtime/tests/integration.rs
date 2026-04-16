// SPDX-License-Identifier: Apache-2.0
use vs_crypto::{CryptoProvider, KeyId, KeyType};
use vs_runtime::{
    CanFrame, CratonShield, EthPacket, PlatformConfig, SubsystemStatus, WatchdogAction,
};
use vs_types::VsError;

// ---------------------------------------------------------------------------
// TestCrypto -- minimal mock CryptoProvider for integration tests
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct TestCrypto;

impl CryptoProvider for TestCrypto {
    fn aes_gcm_encrypt(
        &self,
        _: KeyId,
        _: &[u8; 12],
        _: &[u8],
        _: &[u8],
        _: &mut [u8],
        _: &mut [u8; 16],
    ) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }
    fn aes_gcm_decrypt(
        &self,
        _: KeyId,
        _: &[u8; 12],
        _: &[u8],
        _: &[u8],
        _: &[u8; 16],
        _: &mut [u8],
    ) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }
    fn sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError> {
        // Return a non-zero deterministic hash. V9: different inputs must
        // produce different outputs to pass the enhanced KAT.
        *hash_out = [0x42; 32];
        for (i, &b) in data.iter().enumerate() {
            hash_out[i % 32] ^= b;
            hash_out[(i + 7) % 32] = hash_out[(i + 7) % 32].wrapping_add(b);
        }
        Ok(())
    }
    fn hmac_sha256(&self, _: KeyId, _: &[u8], mac_out: &mut [u8; 32]) -> Result<(), VsError> {
        *mac_out = [0xAA; 32];
        Ok(())
    }
    fn ecdh_derive_shared(&self, _: KeyId, _: &[u8; 65], _: &mut [u8; 32]) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }
    fn sign_p256(&self, _: KeyId, _: &[u8; 32], _: &mut [u8; 64]) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }
    fn verify_p256(&self, _: &[u8; 65], _: &[u8; 32], _: &[u8; 64]) -> Result<bool, VsError> {
        Ok(true)
    }
    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), VsError> {
        // Use a simple counter to produce non-uniform bytes, satisfying
        // the RNG health check in CratonShield::init().
        for (i, b) in buf.iter_mut().enumerate() {
            *b = 0x42_u8.wrapping_add(i as u8);
        }
        Ok(())
    }
    fn delete_key(&mut self, _key_id: KeyId) -> Result<(), VsError> {
        Ok(())
    }
    fn generate_key(&mut self, _key_id: KeyId, _key_type: KeyType) -> Result<(), VsError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_config() -> PlatformConfig {
    PlatformConfig {
        watchdog_timeout_us: 1_000_000,
        watchdog_action: WatchdogAction::Reset,
        ids_correlation_window_us: 100_000,
    }
}

fn make_can_frame(id: u32, dlc: u8, byte_fill: u8) -> CanFrame {
    CanFrame {
        id,
        is_extended: false,
        is_fd: false,
        dlc,
        data: [byte_fill; 64],
    }
}

fn make_eth_packet(payload: &[u8]) -> EthPacket<'_> {
    EthPacket {
        src_mac: [0xAA; 6],
        dst_mac: [0xBB; 6],
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload,
    }
}

// ---------------------------------------------------------------------------
// Initialization & Health Tests
// ---------------------------------------------------------------------------

#[test]
fn test_runtime_initialization_and_can_alert_routing() {
    let mut vs =
        CratonShield::init(default_config(), TestCrypto).expect("platform init should succeed");

    assert!(vs.is_initialized());
    let health = vs.health_status();
    // Core subsystems are Ready immediately:
    assert_eq!(health.crypto, SubsystemStatus::Ready);
    assert_eq!(health.ids_engine, SubsystemStatus::Ready);
    assert_eq!(health.firewall, SubsystemStatus::Ready);
    assert_eq!(health.key_manager, SubsystemStatus::Ready);
    assert_eq!(health.can_monitor, SubsystemStatus::Ready);
    assert_eq!(health.eth_monitor, SubsystemStatus::Ready);
    assert_eq!(health.anomaly, SubsystemStatus::Ready);
    assert_eq!(health.integrity, SubsystemStatus::Ready);
    assert_eq!(health.policy_engine, SubsystemStatus::Ready);
    // Subsystems requiring explicit setup stay NotInitialized:
    assert_eq!(health.ota_validator, SubsystemStatus::NotInitialized);
    assert_eq!(health.secure_boot, SubsystemStatus::NotInitialized);
    assert_eq!(health.storage, SubsystemStatus::NotInitialized);
    assert_eq!(health.hal, SubsystemStatus::NotInitialized);

    // With no policy rules loaded, frame submission is denied (fail-closed).
    let frame1 = make_can_frame(0x123, 8, 0x00);
    assert_eq!(
        vs.submit_can_frame(&frame1, 1000),
        Err(VsError::PolicyViolation),
        "CAN frame should be denied when no rules are loaded"
    );

    let tagged_pkt = EthPacket {
        src_mac: [1, 2, 3, 4, 5, 6],
        dst_mac: [6, 5, 4, 3, 2, 1],
        vlan_id: Some(42),
        ethertype: 0x0800,
        dst_port: None,
        payload: &[0; 32],
    };
    assert_eq!(
        vs.submit_eth_packet(&tagged_pkt, 2000),
        Err(VsError::PolicyViolation),
        "ETH packet should be denied when no rules are loaded"
    );
}

#[test]
fn test_runtime_tick_and_watchdog() {
    let mut config = default_config();
    config.watchdog_timeout_us = 5_000_000;

    let mut vs = CratonShield::<TestCrypto>::new(&config).expect("platform init");

    vs.tick(1_000_000).expect("tick should succeed");
    assert_eq!(vs.tick_count(), 1);

    assert!(vs.check_watchdog(2_000_000).is_none());
    assert!(vs.check_watchdog(8_000_000).is_some());
}

#[test]
fn test_shutdown_marks_all_not_initialized() {
    let mut vs =
        CratonShield::init(default_config(), TestCrypto).expect("platform init should succeed");
    assert!(vs.is_initialized());

    vs.shutdown();
    assert!(!vs.is_initialized());

    let health = vs.health_status();
    assert_eq!(health.crypto, SubsystemStatus::NotInitialized);
    assert_eq!(health.can_monitor, SubsystemStatus::NotInitialized);
    assert_eq!(health.ids_engine, SubsystemStatus::NotInitialized);
    assert_eq!(health.firewall, SubsystemStatus::NotInitialized);
    assert_eq!(health.policy_engine, SubsystemStatus::NotInitialized);
}

#[test]
fn test_tick_after_shutdown_returns_not_initialized() {
    let mut vs =
        CratonShield::init(default_config(), TestCrypto).expect("platform init should succeed");
    vs.shutdown();
    assert_eq!(vs.tick(1_000), Err(VsError::NotInitialized));
}

#[test]
fn test_submit_can_frame_after_shutdown_returns_not_initialized() {
    let mut vs =
        CratonShield::init(default_config(), TestCrypto).expect("platform init should succeed");
    vs.shutdown();
    let frame = make_can_frame(0x100, 8, 0x00);
    assert_eq!(
        vs.submit_can_frame(&frame, 1_000),
        Err(VsError::NotInitialized)
    );
}

#[test]
fn test_submit_eth_packet_after_shutdown_returns_not_initialized() {
    let mut vs =
        CratonShield::init(default_config(), TestCrypto).expect("platform init should succeed");
    vs.shutdown();
    let pkt = make_eth_packet(&[0; 32]);
    assert_eq!(
        vs.submit_eth_packet(&pkt, 1_000),
        Err(VsError::NotInitialized)
    );
}

#[test]
fn test_double_shutdown_does_not_panic() {
    let mut vs =
        CratonShield::init(default_config(), TestCrypto).expect("platform init should succeed");
    vs.shutdown();
    vs.shutdown();
    assert!(!vs.is_initialized());
}

#[test]
fn test_can_frame_denied_without_rules() {
    let mut vs =
        CratonShield::init(default_config(), TestCrypto).expect("platform init should succeed");

    // With no policy rules loaded, CAN frames are denied (fail-closed).
    for i in 0..5u64 {
        let frame = make_can_frame(0x100 + (i as u32 % 8), 8, 0x01);
        assert_eq!(
            vs.submit_can_frame(&frame, i * 20_000),
            Err(VsError::PolicyViolation)
        );
    }
}

#[test]
fn test_eth_packet_denied_without_rules() {
    let mut vs =
        CratonShield::init(default_config(), TestCrypto).expect("platform init should succeed");

    // With no policy rules loaded, ETH packets are denied (fail-closed).
    let payload = [0x42u8; 64];
    let pkt = make_eth_packet(&payload);
    for i in 0..5u64 {
        assert_eq!(
            vs.submit_eth_packet(&pkt, i * 20_000),
            Err(VsError::PolicyViolation)
        );
    }
}

#[test]
fn test_mixed_can_and_eth_traffic_denied_without_rules() {
    let mut vs =
        CratonShield::init(default_config(), TestCrypto).expect("platform init should succeed");

    let frame = make_can_frame(0x200, 8, 0xDD);
    let payload = [0xEE; 64];
    let pkt = make_eth_packet(&payload);

    // With no policy rules loaded, all traffic is denied (fail-closed).
    for i in 0..5u64 {
        let ts = i * 10_000;
        assert_eq!(
            vs.submit_can_frame(&frame, ts),
            Err(VsError::PolicyViolation)
        );
        assert_eq!(
            vs.submit_eth_packet(&pkt, ts + 5_000),
            Err(VsError::PolicyViolation)
        );
    }

    assert_eq!(vs.health_status().crypto, SubsystemStatus::Ready);
    assert_eq!(vs.health_status().ids_engine, SubsystemStatus::Ready);
}

#[test]
fn test_tick_advances_counter() {
    let mut vs =
        CratonShield::init(default_config(), TestCrypto).expect("platform init should succeed");

    for i in 1..=100u64 {
        vs.tick(i * 1_000).expect("tick should succeed");
        assert_eq!(vs.tick_count(), i);
    }
}

#[test]
fn test_tick_rejects_backwards_timestamp() {
    let mut vs =
        CratonShield::init(default_config(), TestCrypto).expect("platform init should succeed");
    vs.tick(10_000).expect("tick should succeed");
    assert_eq!(vs.tick(5_000), Err(VsError::InvalidInput));
    // Forward tick still works.
    assert!(vs.tick(20_000).is_ok());
    assert_eq!(vs.tick_count(), 2);
}

#[test]
fn test_subsystem_accessors_available() {
    let vs =
        CratonShield::init(default_config(), TestCrypto).expect("platform init should succeed");

    let _ = vs.policy_engine();
    let _ = vs.firewall();
    let _ = vs.event_logger();
    let _ = vs.anomaly_detector();
    let _ = vs.key_manager();
    let _ = vs.integrity_monitor();
    let _ = vs.ota_validator(); // Returns None until configured
    let _ = vs.boot_verifier();
}

#[test]
fn test_health_stable_after_sustained_ticks() {
    let mut vs =
        CratonShield::init(default_config(), TestCrypto).expect("platform init should succeed");

    // Without policy rules, frames are denied. Verify health remains
    // stable after sustained tick activity.
    for i in 0..200u64 {
        let ts = i * 5_000;
        if i % 10 == 0 {
            vs.tick(ts).expect("tick should succeed");
        }
    }

    let health = vs.health_status();
    assert_eq!(health.crypto, SubsystemStatus::Ready);
    assert_eq!(health.can_monitor, SubsystemStatus::Ready);
    assert_eq!(health.ids_engine, SubsystemStatus::Ready);
    assert_eq!(health.firewall, SubsystemStatus::Ready);
    assert_eq!(health.policy_engine, SubsystemStatus::Ready);
}

#[test]
fn test_reinit_after_shutdown() {
    let mut vs1 =
        CratonShield::init(default_config(), TestCrypto).expect("platform init should succeed");
    vs1.tick(1_000).expect("tick should succeed");
    vs1.shutdown();

    let vs2 =
        CratonShield::init(default_config(), TestCrypto).expect("platform re-init should succeed");
    assert!(vs2.is_initialized());
    assert_eq!(vs2.tick_count(), 0);
    assert_eq!(vs2.health_status().crypto, SubsystemStatus::Ready);
}

// ---------------------------------------------------------------------------
// OTA configuration tests
// ---------------------------------------------------------------------------

#[test]
fn test_ota_not_available_until_configured() {
    let vs =
        CratonShield::init(default_config(), TestCrypto).expect("platform init should succeed");
    assert!(vs.ota_validator().is_none());
    assert_eq!(
        vs.health_status().ota_validator,
        SubsystemStatus::NotInitialized
    );
}

// ---------------------------------------------------------------------------
// Boot verification tests
// ---------------------------------------------------------------------------

#[test]
fn test_boot_not_verified_after_init() {
    let vs =
        CratonShield::init(default_config(), TestCrypto).expect("platform init should succeed");
    assert!(!vs.is_boot_verified());
    assert_eq!(
        vs.health_status().secure_boot,
        SubsystemStatus::NotInitialized
    );
}
