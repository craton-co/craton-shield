// SPDX-License-Identifier: Apache-2.0
use criterion::{black_box, criterion_group, criterion_main, Criterion};

mod bench_helpers;
use bench_helpers::{can_rule, firewall_rule, make_can_frame, make_someip_payload};

use vs_can_monitor::CanMonitor;
use vs_crypto::SoftwareCryptoProvider;
use vs_eth_monitor::{EthMonitor, EthMonitorConfig, EthPacket, DEFAULT_SIPHASH_KEYS};
use vs_event_logger::{EventLog, EventType};
use vs_netfw::{Firewall, RuleAction};
use vs_policy_engine::{
    Action, ActionMatcher, ActionType, Effect, Environment, PolicyEngine, PolicyRule, Resource,
    ResourceMatcher, Subject, SubjectMatcher,
};
use vs_runtime::{CratonShield, PlatformConfig};

// ---------------------------------------------------------------------------
// Helpers (benchmark-specific; shared helpers in bench_helpers.rs)
// ---------------------------------------------------------------------------

fn make_eth_packet(payload: &[u8]) -> EthPacket<'_> {
    EthPacket {
        src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        dst_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload,
    }
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_can_process_frame(c: &mut Criterion) {
    let mut mon = CanMonitor::default();
    // Add 5 rules covering different CAN IDs
    for i in 0..5u32 {
        mon.add_rule(can_rule(0x100 + i, 1_000))
            .expect("benchmark: CAN rule must be added");
    }
    let frame = make_can_frame(0x100, 8, &[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
    let mut ts = 1_000_000u64;

    c.bench_function("can_monitor::process_frame", |b| {
        b.iter(|| {
            ts += 100_000; // well above min_interval to avoid flood alerts
            black_box(mon.process_frame(black_box(&frame), black_box(ts)))
        });
    });
}

fn bench_eth_inspect_packet(c: &mut Criterion) {
    let config = EthMonitorConfig::default();
    let mut mon = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();
    // Add SOME/IP allow entry
    mon.add_allow_entry(vs_eth_monitor::AllowListEntry {
        src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        dst_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        service_id: 0x0001,
    })
    .unwrap();
    let someip_payload = make_someip_payload();

    // SOME/IP packet (ethertype 0x0800 with SOME/IP in payload)
    let pkt = EthPacket {
        src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        dst_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload: &someip_payload,
    };
    let mut ts = 1_000_000u64;

    c.bench_function("eth_monitor::inspect_packet", |b| {
        b.iter(|| {
            ts += 100_000;
            black_box(mon.inspect_packet(black_box(&pkt), black_box(ts)))
        });
    });
}

fn bench_eth_inspect_packet_rejected(c: &mut Criterion) {
    let config = EthMonitorConfig::default();
    let mut mon = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();
    // Add SOME/IP allow entry for service 0x0001 only
    mon.add_allow_entry(vs_eth_monitor::AllowListEntry {
        src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        dst_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        service_id: 0x0001,
    })
    .unwrap();
    // Build a SOME/IP packet with an UNKNOWN service ID (0xFFFF) — forces
    // full allowlist scan and rejection (worst-case path for WCET).
    let mut rejected_payload = make_someip_payload();
    rejected_payload[0] = 0xFF;
    rejected_payload[1] = 0xFF; // service_id = 0xFFFF (not in allowlist)

    let pkt = EthPacket {
        src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        dst_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        vlan_id: None,
        ethertype: 0x0800,
        dst_port: None,
        payload: &rejected_payload,
    };
    let mut ts = 1_000_000u64;

    c.bench_function("eth_monitor::inspect_packet_rejected", |b| {
        b.iter(|| {
            ts += 100_000;
            black_box(mon.inspect_packet(black_box(&pkt), black_box(ts)))
        });
    });
}

fn bench_firewall_evaluate(c: &mut Criterion) {
    let mut group = c.benchmark_group("firewall::evaluate");

    // Benchmark with 128 rules — first match
    {
        let mut fw = Firewall::new();
        for i in 0..128u32 {
            fw.add_rule(firewall_rule(i, (i & 0xFF) as u8, RuleAction::Allow))
                .expect("benchmark: firewall rule must be added");
        }
        let pkt = make_eth_packet(&[]);
        let mut ts = 1_000_000u64;

        group.bench_function("128_rules_first_match", |b| {
            b.iter(|| {
                ts += 1_000;
                black_box(fw.evaluate(black_box(&pkt), black_box(ts)))
            });
        });
    }

    // Benchmark with 128 rules — last match (worst case)
    {
        let mut fw = Firewall::new();
        // Fill 127 rules that don't match (specific MAC filter)
        for i in 0..127u32 {
            let mut rule = firewall_rule(i, (i & 0xFF) as u8, RuleAction::Drop);
            rule.src_mac = Some([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, (i & 0xFF) as u8]);
            fw.add_rule(rule)
                .expect("benchmark: firewall rule must be added");
        }
        // Last rule matches anything
        fw.add_rule(firewall_rule(127, 255, RuleAction::Allow))
            .expect("benchmark: firewall rule must be added");
        let pkt = make_eth_packet(&[]);
        let mut ts = 1_000_000u64;

        group.bench_function("128_rules_last_match", |b| {
            b.iter(|| {
                ts += 1_000;
                black_box(fw.evaluate(black_box(&pkt), black_box(ts)))
            });
        });
    }

    // Benchmark with port-based matching (L4 rules)
    {
        let mut fw = Firewall::new();
        // Add 64 port-based rules that don't match, then one that does
        for i in 0..64u32 {
            let mut rule = firewall_rule(i, (i & 0xFF) as u8, RuleAction::Drop);
            rule.dst_port = Some(8000 + i as u16);
            fw.add_rule(rule)
                .expect("benchmark: firewall rule must be added");
        }
        // Final rule matches our target port
        let mut catch_all = firewall_rule(64, 255, RuleAction::Allow);
        catch_all.dst_port = Some(443);
        fw.add_rule(catch_all)
            .expect("benchmark: firewall rule must be added");

        let pkt = EthPacket {
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            dst_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: Some(443),
            payload: &[],
        };
        let mut ts = 1_000_000u64;

        group.bench_function("64_port_rules_last_match", |b| {
            b.iter(|| {
                ts += 1_000;
                black_box(fw.evaluate(black_box(&pkt), black_box(ts)))
            });
        });
    }

    group.finish();
}

fn bench_policy_evaluate(c: &mut Criterion) {
    let mut engine = PolicyEngine::new();

    // Load 64 rules
    for i in 0..64u32 {
        engine
            .add_rule(PolicyRule {
                id: i,
                subject: SubjectMatcher::EcuRole((i & 0xFF) as u8),
                resource: ResourceMatcher::Any,
                action: ActionMatcher::Read,
                effect: if i % 2 == 0 {
                    Effect::Permit
                } else {
                    Effect::Deny
                },
                priority: (i & 0xFF) as u8,
                valid_from: 0,
                valid_until: 0,
            })
            .expect("benchmark: policy rule must be added");
    }

    let subject = Subject {
        address: 0x0100,
        authenticated: true,
        ecu_role: 99, // won't match any specific rule — forces full scan to default deny
        session_token: 0,
        auth_level: vs_policy_engine::AuthenticationLevel::None,
    };
    let resource = Resource {
        bus_type: None,
        bus_id: None,
        service_id: None,
        firmware_region: None,
    };
    let action = Action {
        action_type: ActionType::Read,
    };
    let env = Environment {
        timestamp_us: 1_000_000,
    };

    c.bench_function("policy_engine::evaluate (64 rules)", |b| {
        b.iter(|| {
            black_box(engine.evaluate(
                black_box(&subject),
                black_box(&resource),
                black_box(&action),
                black_box(&env),
            ))
        });
    });
}

fn bench_event_logger_append(c: &mut Criterion) {
    let crypto = SoftwareCryptoProvider::default();
    let mut log: EventLog<SoftwareCryptoProvider, 64> =
        EventLog::new(vs_types::KeyId(0), &crypto).unwrap();
    let payload = [0xABu8; 64];
    let mut ts = 1_000_000u64;

    c.bench_function("event_logger::append (HMAC-chained)", |b| {
        b.iter(|| {
            ts += 1_000;
            // Ring buffer wraps, so we can keep appending
            black_box(log.append(
                black_box(EventType::SecurityAlert),
                black_box(&payload),
                black_box(ts),
                black_box(&crypto),
            ))
        });
    });
}

fn bench_runtime_tick(c: &mut Criterion) {
    let config = PlatformConfig::default();
    let crypto = SoftwareCryptoProvider::default();
    let mut platform = CratonShield::init(config, crypto).expect("init must succeed");
    let mut ts = 1_000_000u64;

    c.bench_function("runtime::tick", |b| {
        b.iter(|| {
            ts += 100_000;
            black_box(platform.tick(black_box(ts)))
        });
    });
}

fn bench_runtime_submit_can_frame(c: &mut Criterion) {
    let config = PlatformConfig::default();
    let crypto = SoftwareCryptoProvider::default();
    let mut platform = CratonShield::init(config, crypto).expect("init must succeed");
    let frame = make_can_frame(0x200, 8, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    let mut ts = 1_000_000u64;

    c.bench_function("runtime::submit_can_frame", |b| {
        b.iter(|| {
            ts += 100_000;
            black_box(platform.submit_can_frame(black_box(&frame), black_box(ts)))
        });
    });
}

criterion_group!(
    benches,
    bench_can_process_frame,
    bench_eth_inspect_packet,
    bench_eth_inspect_packet_rejected,
    bench_firewall_evaluate,
    bench_policy_evaluate,
    bench_event_logger_append,
    bench_runtime_tick,
    bench_runtime_submit_can_frame,
);
criterion_main!(benches);
