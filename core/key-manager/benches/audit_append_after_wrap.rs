// SPDX-License-Identifier: Apache-2.0
//! Criterion bench for post-wrap audit append cost.
//!
//! Before the per-entry chain-hash refactor, every audit append AFTER the
//! ring had wrapped triggered an O(AUDIT_CAPACITY) SHA-256 recompute of the
//! chain (256 SHA-256 calls per append). With the per-entry chain hashes the
//! post-wrap append cost is a single SHA-256 call, matching the pre-wrap path.
//!
//! This bench measures rotate_key in steady-state post-wrap.
//!
//! Run with:  `cargo bench -p vs-key-manager --features bench`

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use vs_crypto::{KeyId, SoftwareCryptoProvider};
use vs_key_manager::{KeyAlgorithm, KeyManager, KeyMetadata, KeyPurpose};

fn make_meta(key_id: KeyId) -> KeyMetadata {
    KeyMetadata {
        key_id,
        algorithm: KeyAlgorithm::Aes256Gcm,
        purpose: KeyPurpose::BusAuthentication,
        created_at: 1000,
        expires_at: None,
        rotation_count: 0,
        cumulative_nonce_count: 0,
    }
}

/// Build a non-uniform 32-byte key material array. `validate_key_material`
/// rejects all-zero and uniform-byte slices, so each bench-key must differ
/// across at least two bytes.
fn make_material(seed: u8) -> [u8; 32] {
    let mut mat = [0u8; 32];
    for (i, b) in mat.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8).wrapping_add(1);
    }
    mat
}

fn bench_post_wrap_append(c: &mut Criterion) {
    c.bench_function("audit_append_after_wrap", |b| {
        // Build a manager whose audit ring has already wrapped.
        let crypto = SoftwareCryptoProvider::default();
        let mut mgr: KeyManager<SoftwareCryptoProvider> = KeyManager::new(crypto);
        let initial = make_material(0x10);
        mgr.provision_key(KeyId(0), make_meta(KeyId(0)), &initial)
            .expect("provision");
        // 600 rotations is well past the 256-entry capacity.
        for i in 0..600u64 {
            let mat = make_material((i & 0xFF) as u8);
            mgr.rotate_key(KeyId(0), &mat, 2000 + i, None)
                .expect("rotate");
        }

        let mut t: u64 = 100_000;
        b.iter(|| {
            t += 1;
            let mat = make_material((t & 0xFF) as u8);
            let _ = mgr.rotate_key(black_box(KeyId(0)), black_box(&mat), black_box(t), None);
        });
    });
}

criterion_group!(benches, bench_post_wrap_append);
criterion_main!(benches);
