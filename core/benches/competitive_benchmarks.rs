// SPDX-License-Identifier: Apache-2.0
//! Competitive benchmark suite for Craton Shield Core.
//!
//! Compares Craton Shield's hot-path operations against:
//! - **Baseline primitives**: raw hash, memcmp, array scan (quantifies framework overhead)
//! - **Scaling behavior**: measures throughput at different rule/entry counts
//! - **Crypto baselines**: software AES-GCM / SHA-256 / HMAC vs Craton's `CryptoProvider`
//!
//! Run with:
//!   `cargo bench --bench competitive_benchmarks`
//!
//! ## CI performance budgets
//!
//! These benchmarks feed the scaling tables in `core/docs/performance-results.md`.
//! The headline budgets (per-element targets at the top end of each scaling
//! sweep, sourced from `PERFORMANCE.md`):
//!
//! | Group / size                          | v0.7.0 mean | CI budget |
//! |---------------------------------------|-------------|-----------|
//! | `firewall_scaling/last_match/128`     |    ~190 ns  |   230 ns  |
//! | `policy_scaling/first_match_miss/64`  |    ~227 ns  |   280 ns  |
//! | `can_scaling/process_frame/64`        |    ~320 ns  |   400 ns  |
//! | `crypto/sha256/256`                   |    ~461 ns  |   600 ns  |
//! | `crypto/hmac_sha256/64`               |    ~276 ns  |   350 ns  |
//! | `crypto/aes_gcm_encrypt/256`          |    ~907 ns  |  1100 ns  |
//!
//! `Throughput::{Elements, Bytes}` is set per group so criterion reports a
//! per-element rate alongside the latency.

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};

mod bench_helpers;
use bench_helpers::{can_rule, firewall_rule, make_can_frame};

use vs_can_monitor::CanMonitor;
use vs_crypto::{CryptoProvider, SoftwareCryptoProvider};
use vs_eth_monitor::EthPacket;
use vs_event_logger::{EventLog, EventType};
use vs_netfw::{Firewall, RuleAction};
use vs_policy_engine::{
    Action, ActionMatcher, ActionType, Effect, Environment, PolicyEngine, PolicyRule, Resource,
    ResourceMatcher, Subject, SubjectMatcher,
};
use vs_runtime::{CratonShield, PlatformConfig};
use vs_types::KeyId;

// ---------------------------------------------------------------------------
// Helpers
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
// 1. Firewall scaling: 8, 32, 64, 128 rules (first-match vs last-match)
// ---------------------------------------------------------------------------

fn bench_firewall_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("competitive/firewall_scaling");
    group.throughput(Throughput::Elements(1));

    for &rule_count in &[8u32, 32, 64, 128] {
        // First match: the first rule matches
        {
            let mut fw = Firewall::new();
            for i in 0..rule_count {
                fw.add_rule(firewall_rule(i, (i & 0xFF) as u8, RuleAction::Allow))
                    .unwrap();
            }
            let pkt = make_eth_packet(&[]);
            let mut ts = 1_000_000u64;

            group.bench_with_input(
                BenchmarkId::new("first_match", rule_count),
                &rule_count,
                |b, _| {
                    b.iter(|| {
                        ts += 1_000;
                        black_box(fw.evaluate(black_box(&pkt), black_box(ts)))
                    });
                },
            );
        }

        // Last match: only the last rule matches
        {
            let mut fw = Firewall::new();
            for i in 0..rule_count.saturating_sub(1) {
                let mut rule = firewall_rule(i, (i & 0xFF) as u8, RuleAction::Drop);
                rule.src_mac = Some([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, (i & 0xFF) as u8]);
                fw.add_rule(rule).unwrap();
            }
            fw.add_rule(firewall_rule(rule_count - 1, 255, RuleAction::Allow))
                .unwrap();
            let pkt = make_eth_packet(&[]);
            let mut ts = 1_000_000u64;

            group.bench_with_input(
                BenchmarkId::new("last_match", rule_count),
                &rule_count,
                |b, _| {
                    b.iter(|| {
                        ts += 1_000;
                        black_box(fw.evaluate(black_box(&pkt), black_box(ts)))
                    });
                },
            );
        }
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 2. Policy engine scaling: 8, 16, 32, 64 rules
// ---------------------------------------------------------------------------

fn bench_policy_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("competitive/policy_scaling");
    group.throughput(Throughput::Elements(1));

    let subject = Subject {
        address: 0x0100,
        authenticated: true,
        ecu_role: 99,
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

    for &rule_count in &[8u32, 16, 32, 64] {
        let mut engine = PolicyEngine::new();
        for i in 0..rule_count {
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
                .unwrap();
        }

        group.bench_with_input(
            BenchmarkId::new("first_match_miss", rule_count),
            &rule_count,
            |b, _| {
                b.iter(|| {
                    black_box(engine.evaluate(
                        black_box(&subject),
                        black_box(&resource),
                        black_box(&action),
                        black_box(&env),
                    ))
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 3. CAN monitor: varying rule counts
// ---------------------------------------------------------------------------

fn bench_can_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("competitive/can_scaling");
    group.throughput(Throughput::Elements(1));

    for &rule_count in &[1u32, 5, 16, 64] {
        let mut mon = CanMonitor::default();
        for i in 0..rule_count {
            mon.add_rule(can_rule(0x100 + i, 1_000)).unwrap();
        }
        let frame = make_can_frame(0x100, 8, &[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
        let mut ts = 1_000_000u64;

        group.bench_with_input(
            BenchmarkId::new("process_frame", rule_count),
            &rule_count,
            |b, _| {
                b.iter(|| {
                    ts += 100_000;
                    black_box(mon.process_frame(black_box(&frame), black_box(ts)))
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 4. Crypto baselines: SHA-256, HMAC-SHA256, AES-GCM at different sizes
// ---------------------------------------------------------------------------

fn bench_crypto_baselines(c: &mut Criterion) {
    let mut group = c.benchmark_group("competitive/crypto");
    let mut crypto = SoftwareCryptoProvider::default();

    // Provision key slot 0 so HMAC and AES-GCM benchmarks have a key to use.
    let test_key = [0x42u8; 32];
    crypto
        .set_key(KeyId(0), &test_key)
        .expect("set key for benchmarks");

    // SHA-256 at different input sizes
    for &size in &[64usize, 256, 1024, 4096] {
        let data = vec![0x55u8; size];
        let mut hash = [0u8; 32];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("sha256", size), &size, |b, _| {
            b.iter(|| {
                crypto.sha256(black_box(&data), &mut hash).unwrap();
            });
        });
    }

    // HMAC-SHA256 at different input sizes
    for &size in &[32usize, 64, 128, 256] {
        let data = vec![0x77u8; size];
        let mut mac = [0u8; 32];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("hmac_sha256", size), &size, |b, _| {
            b.iter(|| {
                crypto
                    .hmac_sha256(KeyId(0), black_box(&data), &mut mac)
                    .unwrap();
            });
        });
    }

    // AES-GCM encrypt at different sizes
    {
        let mut nonce_counter: u64 = 0;
        let aad = [0u8; 0];

        for &size in &[64usize, 128, 256, 1024] {
            let plaintext = vec![0x42u8; size];
            let mut ciphertext = vec![0u8; size];
            let mut tag = [0u8; 16];

            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(BenchmarkId::new("aes_gcm_encrypt", size), &size, |b, _| {
                b.iter(|| {
                    let mut nonce = [0u8; 12];
                    nonce[4..12].copy_from_slice(&nonce_counter.to_be_bytes());
                    nonce_counter += 1;
                    crypto
                        .aes_gcm_encrypt(
                            KeyId(0),
                            &nonce,
                            black_box(&plaintext),
                            &aad,
                            &mut ciphertext,
                            &mut tag,
                        )
                        .unwrap();
                });
            });
        }
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 5. End-to-end throughput: frames per second under load
// ---------------------------------------------------------------------------

fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("competitive/throughput");

    // Measure how many CAN frames can be processed per runtime tick cycle
    {
        let config = PlatformConfig::default();
        let crypto = SoftwareCryptoProvider::default();
        let mut platform = CratonShield::init(config, crypto).expect("init");
        let frame = make_can_frame(0x200, 8, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let mut ts = 1_000_000u64;

        // Submit N frames then tick
        for &batch_size in &[1u32, 10, 50] {
            group.throughput(Throughput::Elements(u64::from(batch_size)));
            group.bench_with_input(
                BenchmarkId::new("submit_n_frames_then_tick", batch_size),
                &batch_size,
                |b, &n| {
                    b.iter(|| {
                        for _ in 0..n {
                            ts += 10_000;
                            let _ = black_box(
                                platform.submit_can_frame(black_box(&frame), black_box(ts)),
                            );
                        }
                        ts += 100_000;
                        let _ = black_box(platform.tick(black_box(ts)));
                    });
                },
            );
        }
    }

    // Event log append throughput (N appends in sequence)
    {
        let mut crypto = SoftwareCryptoProvider::default();
        crypto
            .set_key(KeyId(0), &[0x42u8; 32])
            .expect("set HMAC key for event log bench");
        let mut log: EventLog<SoftwareCryptoProvider, 256> =
            EventLog::new(KeyId(0), &crypto).unwrap();
        let payload = [0xABu8; 64];
        let mut ts = 1_000_000u64;

        for &batch_size in &[1u32, 10, 50] {
            group.throughput(Throughput::Elements(u64::from(batch_size)));
            group.bench_with_input(
                BenchmarkId::new("event_log_append_batch", batch_size),
                &batch_size,
                |b, &n| {
                    b.iter(|| {
                        for _ in 0..n {
                            ts += 1_000;
                            black_box(
                                log.append(EventType::SecurityAlert, &payload, ts, &crypto)
                                    .unwrap(),
                            );
                        }
                    });
                },
            );
        }
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 6. Baseline comparisons: raw operations vs framework overhead
// ---------------------------------------------------------------------------

fn bench_baselines(c: &mut Criterion) {
    let mut group = c.benchmark_group("competitive/baselines");

    // Baseline: raw MAC comparison (what firewall L2 matching does)
    {
        let mac_a = [0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mac_b = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        group.bench_function("raw_mac_compare", |b| {
            b.iter(|| black_box(black_box(mac_a) == black_box(mac_b)));
        });
    }

    // Baseline: linear scan of 128 u8 comparisons (what priority matching does)
    {
        let priorities: [u8; 128] = core::array::from_fn(|i| i as u8);
        let target: u8 = 64;

        group.bench_function("linear_scan_128_u8", |b| {
            b.iter(|| {
                let mut found = false;
                for &p in black_box(&priorities) {
                    if p == black_box(target) {
                        found = true;
                        break;
                    }
                }
                black_box(found)
            });
        });
    }

    // Baseline: FNV-1a hash of 14 bytes (what ETH allow-list hash does)
    {
        let data = [0u8; 14];

        group.bench_function("fnv1a_14bytes", |b| {
            b.iter(|| {
                let mut h: u64 = 0xcbf2_9ce4_8422_2325;
                for &byte in black_box(&data) {
                    h ^= byte as u64;
                    h = h.wrapping_mul(0x0100_0000_01b3);
                }
                black_box(h)
            });
        });
    }

    group.finish();
}

criterion_group!(
    competitive,
    bench_firewall_scaling,
    bench_policy_scaling,
    bench_can_scaling,
    bench_crypto_baselines,
    bench_throughput,
    bench_baselines,
);
criterion_main!(competitive);
