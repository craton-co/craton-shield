// SPDX-License-Identifier: Apache-2.0
//! Shared test helpers for Craton Shield integration tests.

use vs_can_monitor::{CanFrame, CanRule};
use vs_crypto::SoftwareCryptoProvider;
use vs_eth_monitor::{EthMonitor, EthMonitorConfig, EthPacket, DEFAULT_SIPHASH_KEYS};
use vs_netfw::{FirewallRule, RuleAction};
use vs_policy_engine::{ActionMatcher, Effect, PolicyRule, ResourceMatcher, SubjectMatcher};
use vs_runtime::CratonShield;
use vs_types::AlertSeverity;
use vs_types::KeyId;

// ---------------------------------------------------------------------------
// Deterministic RNG
// ---------------------------------------------------------------------------

/// Deterministic RNG for tests — produces a repeatable byte sequence.
pub fn test_rng(buf: &mut [u8]) {
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_add(0x42);
    }
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

/// Build a `SoftwareCryptoProvider` with key slot 0 provisioned.
#[allow(dead_code)]
pub fn make_crypto() -> SoftwareCryptoProvider {
    let mut cp = SoftwareCryptoProvider::new(test_rng);
    cp.set_key(KeyId(0), &[0xAA; 32]).expect("provision key 0");
    cp
}

/// Build a `SoftwareCryptoProvider` with a different key (for runtime tests
/// that use `0x42` fill).
#[allow(dead_code)]
pub fn make_crypto_runtime() -> SoftwareCryptoProvider {
    let mut cp = SoftwareCryptoProvider::new(test_rng);
    cp.set_key(KeyId(0), &[0x42; 32]).expect("provision key 0");
    cp
}

// ---------------------------------------------------------------------------
// CAN helpers
// ---------------------------------------------------------------------------

/// Build a CAN frame with the given ID, DLC, and data fill.
#[allow(dead_code)]
pub fn make_can_frame(id: u32, dlc: u8, data: &[u8]) -> CanFrame {
    let mut frame = CanFrame {
        id,
        is_extended: false,
        is_fd: false,
        dlc,
        data: [0u8; 64],
    };
    let copy_len = data.len().min(64);
    frame.data[..copy_len].copy_from_slice(&data[..copy_len]);
    frame
}

/// Build a CAN frame filled with a single byte value.
#[allow(dead_code)]
pub fn make_can_frame_fill(id: u32, dlc: u8, byte_fill: u8) -> CanFrame {
    CanFrame {
        id,
        is_extended: false,
        is_fd: false,
        dlc,
        data: [byte_fill; 64],
    }
}

/// Build a rule matching a single exact standard CAN ID.
#[allow(dead_code)]
pub fn exact_id_rule(id: u32, min_interval_us: u64, max_dlc: u8) -> CanRule {
    CanRule {
        id: 0,
        id_mask: 0x7FF,
        id_filter: id,
        min_interval_us,
        max_dlc,
        is_extended: false,
        severity: AlertSeverity::High,
    }
}

// ---------------------------------------------------------------------------
// Ethernet helpers
// ---------------------------------------------------------------------------

/// Build a simple Ethernet packet with the given payload.
#[allow(dead_code)]
pub fn make_eth_packet(payload: &[u8]) -> EthPacket<'_> {
    EthPacket {
        src_mac: [0xAA; 6],
        dst_mac: [0xBB; 6],
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload,
    }
}

/// Build a default `EthMonitor` with the given config.
#[allow(dead_code)]
pub fn make_eth_monitor() -> EthMonitor {
    EthMonitor::new(&EthMonitorConfig::default(), DEFAULT_SIPHASH_KEYS).unwrap()
}

// ---------------------------------------------------------------------------
// Policy / Firewall helpers
// ---------------------------------------------------------------------------

/// Load a permit-all policy rule and an allow-all firewall rule so that
/// CAN/ETH submission tests pass under the fail-closed defaults.
#[allow(dead_code)]
pub fn allow_all_traffic(shield: &mut CratonShield<SoftwareCryptoProvider>) {
    shield
        .policy_engine_mut()
        .add_rule(PolicyRule {
            id: 1,
            subject: SubjectMatcher::Any,
            resource: ResourceMatcher::Any,
            action: ActionMatcher::Any,
            effect: Effect::Permit,
            priority: 0,
            valid_from: 0,
            valid_until: 0,
        })
        .expect("add permit-all policy rule");
    shield
        .firewall_mut()
        .add_rule(FirewallRule {
            id: 1,
            priority: 0,
            action: RuleAction::Allow,
            active: true,
            ..FirewallRule::default()
        })
        .expect("add allow-all firewall rule");
}
