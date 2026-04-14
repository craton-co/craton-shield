// SPDX-License-Identifier: Apache-2.0
//! Standalone WCET measurement harness.
//!
//! Measures worst-case execution time for all critical-path operations defined
//! in `docs/wcet-protocol.md`. Uses hardware cycle counters (PMCCNTR on
//! aarch64, RDTSC on x86_64) or `std::time::Instant` as fallback.
//!
//! Build:
//!   `cargo build --release --bin wcet-harness --features wcet`
//!
//! Run:
//!   `./target/release/wcet-harness`

use std::hint::black_box;

#[path = "bench_helpers.rs"]
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
use vs_types::KeyId;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const ITERATIONS: usize = 10_000;
const WARMUP: usize = 100;
/// Safety margin added on top of observed max to estimate WCET.
/// This is a heuristic, not a formal WCET bound. See docs/wcet-protocol.md.
const WCET_MARGIN_PERCENT: u64 = 20;

// ---------------------------------------------------------------------------
// Cycle counter abstraction
// ---------------------------------------------------------------------------

#[allow(unsafe_code)]
fn read_cycles() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        let count: u64;
        // SAFETY: reads the aarch64 performance monitor cycle counter register.
        // This is a read-only operation with no side effects beyond returning
        // the current cycle count. Requires EL0 access to PMCCNTR_EL0.
        unsafe {
            core::arch::asm!("mrs {}, pmccntr_el0", out(reg) count);
        }
        return count;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let lo: u64;
        let hi: u64;
        // SAFETY: lfence + rdtsc is a standard serializing timestamp read on
        // x86_64. lfence ensures prior instructions complete before rdtsc
        // executes, preventing undercount of cycles in WCET measurement.
        // Both instructions are read-only with no side effects.
        unsafe {
            core::arch::asm!("lfence", "rdtsc", out("rax") lo, out("rdx") hi);
        }
        return (hi << 32) | lo;
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        // Fallback: monotonic nanosecond timestamp (not cycles, but usable for
        // relative elapsed-time measurement when paired with wrapping_sub).
        // Uses Instant (monotonic) rather than SystemTime to avoid backwards
        // jumps from NTP adjustments that would corrupt WCET statistics.
        use std::sync::OnceLock;
        use std::time::Instant;
        static EPOCH: OnceLock<Instant> = OnceLock::new();
        let epoch = EPOCH.get_or_init(Instant::now);
        epoch.elapsed().as_nanos() as u64
    }
}

/// Issue memory barriers (aarch64 only). No-op on other architectures.
///
/// Note: this does NOT actually flush data caches (that would require
/// `dc civac` per cache line, which typically needs kernel privilege).
/// It only provides a data synchronization barrier + instruction barrier
/// to ensure prior memory operations complete before measurement starts.
#[allow(unsafe_code)]
fn memory_barrier() {
    #[cfg(target_arch = "aarch64")]
    // SAFETY: dsb sy + isb are memory/instruction barriers with no side effects
    // beyond ensuring prior memory operations are visible before measurement.
    unsafe {
        core::arch::asm!("dsb sy");
        core::arch::asm!("isb");
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct WcetResult {
    operation: &'static str,
    min: u64,
    max: u64,
    mean: f64,
    median: u64,
    p99: u64,
    p999: u64,
    wcet: u64,
    budget_us: f64,
}

fn compute_stats(name: &'static str, samples: &mut [u64], budget_us: f64) -> WcetResult {
    samples.sort_unstable();
    let n = samples.len();
    let min = samples[0];
    let max = samples[n - 1];
    let sum: u128 = samples.iter().map(|&s| s as u128).sum();
    let mean = sum as f64 / n as f64;
    let median = samples[n / 2];
    let p99 = samples[(n as f64 * 0.99) as usize];
    let p999 = samples[((n as f64 * 0.999) as usize).min(n - 1)];
    let wcet = max + max / (100 / WCET_MARGIN_PERCENT);

    WcetResult {
        operation: name,
        min,
        max,
        mean,
        median,
        p99,
        p999,
        wcet,
        budget_us,
    }
}

// Setup helpers are in bench_helpers.rs (shared with criterion benchmarks).

// ---------------------------------------------------------------------------
// Measurement runner
// ---------------------------------------------------------------------------

fn measure<F: FnMut()>(name: &'static str, budget_us: f64, mut f: F) -> WcetResult {
    // Warmup
    for _ in 0..WARMUP {
        black_box(f());
    }

    let mut samples = vec![0u64; ITERATIONS];
    for s in &mut samples {
        memory_barrier();
        let start = read_cycles();
        black_box(f());
        let end = read_cycles();
        *s = end.wrapping_sub(start);
    }

    compute_stats(name, &mut samples, budget_us)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    println!("Craton Shield WCET Measurement Harness");
    println!("=======================================");
    println!("Iterations: {ITERATIONS}  Warmup: {WARMUP}");

    #[cfg(target_arch = "aarch64")]
    println!("Counter: PMCCNTR_EL0 (ARM cycle counter)");
    #[cfg(target_arch = "x86_64")]
    println!("Counter: RDTSC (x86_64 timestamp counter)");
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    println!("Counter: std::time::Instant (fallback)");

    println!();

    let mut results = Vec::new();

    // 1. CAN process_frame (5 detectors)
    {
        let mut mon = CanMonitor::default();
        for i in 0..5u32 {
            mon.add_rule(can_rule(0x100 + i, 1_000))
                .expect("wcet: CAN rule must be added");
        }
        let frame = make_can_frame(0x100, 8, &[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
        let mut ts = 1_000_000u64;
        results.push(measure("can_process_frame", 10.0, || {
            ts += 100_000;
            black_box(mon.process_frame(&frame, ts));
        }));
    }

    // 2. ETH inspect_packet
    {
        let config = EthMonitorConfig::default();
        let mut mon = EthMonitor::new(&config, DEFAULT_SIPHASH_KEYS).unwrap();
        let payload = make_someip_payload();
        let pkt = EthPacket {
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            dst_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &payload,
        };
        let mut ts = 1_000_000u64;
        results.push(measure("eth_inspect_packet", 10.0, || {
            ts += 100_000;
            black_box(mon.inspect_packet(&pkt, ts));
        }));
    }

    // 3. Firewall evaluate (128 rules, first match)
    {
        let mut fw = Firewall::new();
        for i in 0..128u32 {
            fw.add_rule(firewall_rule(i, (i & 0xFF) as u8, RuleAction::Allow))
                .expect("wcet: firewall rule must be added");
        }
        let pkt = EthPacket {
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            dst_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &[],
        };
        let mut ts = 1_000_000u64;
        results.push(measure("firewall_128_first_match", 10.0, || {
            ts += 1_000;
            black_box(fw.evaluate(&pkt, ts));
        }));
    }

    // 4. Firewall evaluate (128 rules, last match)
    {
        let mut fw = Firewall::new();
        for i in 0..127u32 {
            let mut rule = firewall_rule(i, (i & 0xFF) as u8, RuleAction::Drop);
            rule.src_mac = Some([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, (i & 0xFF) as u8]);
            fw.add_rule(rule)
                .expect("wcet: firewall rule must be added");
        }
        fw.add_rule(firewall_rule(127, 255, RuleAction::Allow))
            .expect("wcet: firewall rule must be added");
        let pkt = EthPacket {
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            dst_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            vlan_id: None,
            ethertype: 0x0800,
            dst_port: None,
            payload: &[],
        };
        let mut ts = 1_000_000u64;
        results.push(measure("firewall_128_last_match", 10.0, || {
            ts += 1_000;
            black_box(fw.evaluate(&pkt, ts));
        }));
    }

    // 5. Policy evaluate (64 rules)
    {
        let mut engine = PolicyEngine::new();
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
                .expect("wcet: policy rule must be added");
        }
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
        results.push(measure("policy_evaluate_64", 10.0, || {
            black_box(engine.evaluate(&subject, &resource, &action, &env));
        }));
    }

    // 6. Event logger append (HMAC-chained)
    {
        let crypto = SoftwareCryptoProvider::default();
        let mut log: EventLog<SoftwareCryptoProvider, 64> =
            EventLog::new(KeyId(0), &crypto).unwrap();
        let payload = [0xABu8; 64];
        let mut ts = 1_000_000u64;
        results.push(measure("event_logger_append", 10.0, || {
            ts += 1_000;
            black_box(
                log.append(EventType::SecurityAlert, &payload, ts, &crypto)
                    .expect("wcet: event log append failed"),
            );
        }));
    }

    // 7. Runtime tick
    {
        let config = PlatformConfig::default();
        let crypto = SoftwareCryptoProvider::default();
        let mut platform = CratonShield::init(config, crypto).expect("init");
        let mut ts = 1_000_000u64;
        results.push(measure("runtime_tick", 10.0, || {
            ts += 100_000;
            black_box(platform.tick(ts));
        }));
    }

    // 8. Runtime submit_can_frame
    {
        let config = PlatformConfig::default();
        let crypto = SoftwareCryptoProvider::default();
        let mut platform = CratonShield::init(config, crypto).expect("init");
        let frame = make_can_frame(0x200, 8, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let mut ts = 1_000_000u64;
        results.push(measure("runtime_submit_can_frame", 10.0, || {
            ts += 100_000;
            black_box(platform.submit_can_frame(&frame, ts));
        }));
    }

    // 9. AES-GCM encrypt (128 bytes)
    {
        use vs_crypto::CryptoProvider;
        let crypto = SoftwareCryptoProvider::default();
        // Use a counter-based nonce to avoid nonce reuse. AES-GCM nonce reuse
        // with the same key catastrophically breaks confidentiality and
        // authenticity, so each iteration gets a unique nonce even in benchmarks.
        let mut nonce_counter: u64 = 0;
        let plaintext = [0x42u8; 128];
        let aad = [0u8; 0];
        let mut ciphertext = [0u8; 128];
        let mut tag = [0u8; 16];
        // Verify key slot 0 works before measuring
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&nonce_counter.to_be_bytes());
        crypto
            .aes_gcm_encrypt(
                KeyId(0),
                &nonce,
                &plaintext,
                &aad,
                &mut ciphertext,
                &mut tag,
            )
            .expect("wcet: AES-GCM encrypt must succeed with key slot 0");
        nonce_counter += 1;
        results.push(measure("aes_gcm_encrypt_128B", 50.0, || {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&nonce_counter.to_be_bytes());
            nonce_counter += 1;
            black_box(
                crypto
                    .aes_gcm_encrypt(
                        KeyId(0),
                        &nonce,
                        &plaintext,
                        &aad,
                        &mut ciphertext,
                        &mut tag,
                    )
                    .expect("wcet: AES-GCM encrypt failed"),
            );
        }));
    }

    // 10. SHA-256 (1 KB)
    {
        use vs_crypto::CryptoProvider;
        let crypto = SoftwareCryptoProvider::default();
        let data = [0x55u8; 1024];
        let mut hash = [0u8; 32];
        crypto
            .sha256(&data, &mut hash)
            .expect("wcet: SHA-256 must succeed");
        results.push(measure("sha256_1KB", 50.0, || {
            black_box(
                crypto
                    .sha256(&data, &mut hash)
                    .expect("wcet: SHA-256 failed"),
            );
        }));
    }

    // 11. HMAC-SHA256 (64 bytes)
    {
        use vs_crypto::CryptoProvider;
        let crypto = SoftwareCryptoProvider::default();
        let data = [0x77u8; 64];
        let mut mac = [0u8; 32];
        crypto
            .hmac_sha256(KeyId(0), &data, &mut mac)
            .expect("wcet: HMAC-SHA256 must succeed with key slot 0");
        results.push(measure("hmac_sha256_64B", 50.0, || {
            black_box(
                crypto
                    .hmac_sha256(KeyId(0), &data, &mut mac)
                    .expect("wcet: HMAC-SHA256 failed"),
            );
        }));
    }

    // Print results
    println!();
    println!(
        "{:<30} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>8}",
        "Operation", "Min", "Max", "Mean", "Median", "P99", "P99.9", "WCET", "Budget"
    );
    println!("{}", "-".repeat(120));
    for r in &results {
        println!(
            "{:<30} {:>10} {:>10} {:>10.1} {:>10} {:>10} {:>10} {:>10} {:>7.1}us",
            r.operation, r.min, r.max, r.mean, r.median, r.p99, r.p999, r.wcet, r.budget_us,
        );
    }

    // CSV output
    println!();
    println!("--- CSV ---");
    println!("operation,iterations,min,max,mean,median,p99,p999,wcet,budget_us");
    for r in &results {
        println!(
            "{},{ITERATIONS},{},{},{:.1},{},{},{},{},{:.1}",
            r.operation, r.min, r.max, r.mean, r.median, r.p99, r.p999, r.wcet, r.budget_us,
        );
    }
}
