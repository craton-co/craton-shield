// SPDX-License-Identifier: Apache-2.0
//! Production-ready software `CryptoProvider` using RustCrypto.
//!
//! Unlike `SoftwareCryptoProvider` (mock-hsm, test-only), this implementation
//! uses real cryptographic primitives and is safe for production use on
//! targets without hardware HSM/TPM.
//!
//! # Feature gate
//!
//! Requires the `software` feature:
//!
//! ```toml
//! vs-crypto = { version = "0.7", features = ["software"] }
//! ```
//!
//! # Entropy
//!
//! The caller must supply an entropy function (`fn(&mut [u8])`) that fills
//! the provided buffer with cryptographically secure random bytes. On
//! Linux/QNX this wraps `getrandom(2)`; on bare-metal Cortex-M it reads
//! the hardware TRNG peripheral.
//!
//! # Key storage
//!
//! Keys are stored in RAM in fixed-size slots. All key material is zeroized
//! on `Drop`. For persistent key storage, use a `StorageProvider` backend
//! and re-provision keys after each reboot.

use crate::{CryptoProvider, KeyId, KeyType, NonceTracker};
use subtle::ConstantTimeEq;
use vs_types::VsError;
use zeroize::Zeroize;

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use hkdf::Hkdf;
use hmac::Mac;
use sha2::{Digest, Sha256};

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{AffinePoint, EncodedPoint, PublicKey};

type HmacSha256 = hmac::Hmac<Sha256>;

/// Maximum key slots (matches `vs-key-manager::MAX_KEYS`).
const MAX_KEY_SLOTS: usize = 64;

/// Maximum key material length (AES-256 = 32 bytes, P-256 scalar = 32 bytes).
const MAX_KEY_LEN: usize = 32;

/// Production software crypto provider backed by RustCrypto.
///
/// Provides real AES-256-GCM, SHA-256, HMAC-SHA-256, ECDSA P-256, and
/// ECDH P-256 using the same libraries as `craton-hsm-core`. Keys are
/// stored in stack-allocated slots and zeroized on drop.
///
/// # Thread safety
///
/// This type is `Send` but **not `Sync`** due to the internal `RefCell`
/// used for nonce tracking. It must not be shared across threads via
/// `&RustCryptoProvider`. This matches the intended single-threaded
/// embedded usage model.
///
/// # Example
///
/// ```ignore
/// use vs_crypto::{RustCryptoProvider, KeyId};
///
/// fn platform_rng(buf: &mut [u8]) {
///     // Fill from hardware TRNG or getrandom(2)
/// }
///
/// let mut crypto = RustCryptoProvider::new(platform_rng);
/// crypto.set_key(KeyId(0), &aes_key)?;
/// ```
pub struct RustCryptoProvider {
    keys: [([u8; MAX_KEY_LEN], usize); MAX_KEY_SLOTS],
    rng_fn: fn(&mut [u8]),
    nonce_tracker: core::cell::RefCell<NonceTracker>,
    /// Set to `true` after a self-test failure. When set, all crypto
    /// operations return `CryptoError` to prevent use of a degraded provider.
    self_test_failed: core::cell::Cell<bool>,
}

/// Clone produces a copy with a **fresh** (empty) `NonceTracker` and
/// **erased key material**.  This prevents two dangerous scenarios:
///
/// 1. **Nonce reuse across clones**: each clone starts with its own
///    independent tracker rather than a copy of the original's history.
/// 2. **Shared key material**: if both the original and the clone could
///    encrypt with the same `KeyId`, independent nonce counters would make
///    AES-GCM nonce reuse possible (catastrophic). By clearing keys on
///    clone, the caller must explicitly re-provision only the keys the
///    clone needs, making accidental dual-encryption with the same key
///    impossible.
///
/// Re-provision keys on the clone via [`set_key`](RustCryptoProvider::set_key)
/// or [`generate_key`](CryptoProvider::generate_key) before use.
impl Clone for RustCryptoProvider {
    fn clone(&self) -> Self {
        Self {
            // Erase key material to prevent two providers encrypting with
            // the same key using independent nonce trackers.
            keys: [([0u8; MAX_KEY_LEN], 0); MAX_KEY_SLOTS],
            rng_fn: self.rng_fn,
            // Fresh tracker ensures clones cannot produce overlapping nonces.
            nonce_tracker: core::cell::RefCell::new(crate::NonceTracker::new()),
            // Propagate self-test state: a failed provider's clone is also failed.
            self_test_failed: core::cell::Cell::new(self.self_test_failed.get()),
        }
    }
}

impl core::fmt::Debug for RustCryptoProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RustCryptoProvider")
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

impl Drop for RustCryptoProvider {
    fn drop(&mut self) {
        for slot in &mut self.keys {
            slot.0.zeroize();
            slot.1 = 0;
        }
        let tracker = self.nonce_tracker.get_mut();
        for entry in &mut tracker.ring {
            entry.zeroize();
        }
        tracker.head = 0;
        tracker.count = 0;
        tracker.bloom = [0u64; 4];
    }
}

impl RustCryptoProvider {
    /// Create a new provider with the given entropy source.
    ///
    /// `rng` must fill the buffer with cryptographically secure random bytes.
    /// On Linux/QNX: wrap `getrandom(2)`. On Cortex-M: read the TRNG.
    pub fn new(rng: fn(&mut [u8])) -> Self {
        Self {
            keys: [([0u8; MAX_KEY_LEN], 0); MAX_KEY_SLOTS],
            rng_fn: rng,
            nonce_tracker: core::cell::RefCell::new(NonceTracker::new()),
            self_test_failed: core::cell::Cell::new(false),
        }
    }

    /// Provision key material into a slot.
    ///
    /// `material` must be exactly the right length for the intended use:
    /// - AES-256-GCM: 32 bytes
    /// - HMAC-SHA-256: up to 32 bytes
    /// - ECDSA P-256 / ECDH: 32 bytes (private scalar)
    pub fn set_key(&mut self, slot: KeyId, material: &[u8]) -> Result<(), VsError> {
        let idx = slot.0 as usize;
        if idx >= MAX_KEY_SLOTS {
            return Err(VsError::PolicyViolation);
        }
        if material.is_empty() || material.len() > MAX_KEY_LEN {
            return Err(VsError::InvalidInput);
        }
        self.keys[idx].0 = [0u8; MAX_KEY_LEN];
        self.keys[idx].0[..material.len()].copy_from_slice(material);
        self.keys[idx].1 = material.len();
        Ok(())
    }

    fn get_key(&self, slot: KeyId) -> Result<&[u8], VsError> {
        let idx = slot.0 as usize;
        if idx >= MAX_KEY_SLOTS || self.keys[idx].1 == 0 {
            return Err(VsError::NotInitialized);
        }
        Ok(&self.keys[idx].0[..self.keys[idx].1])
    }

    /// Returns `Err(CryptoError)` if a prior self-test has failed,
    /// preventing use of a degraded crypto provider.
    fn require_operational(&self) -> Result<(), VsError> {
        if self.self_test_failed.get() {
            return Err(VsError::CryptoError);
        }
        Ok(())
    }

    /// Return a 32-byte key for operations that require exactly 32 bytes.
    fn get_key_32(&self, slot: KeyId) -> Result<&[u8; 32], VsError> {
        let key = self.get_key(slot)?;
        if key.len() != 32 {
            return Err(VsError::InvalidInput);
        }
        // Reuse the already-validated slice instead of re-indexing the array,
        // so correctness does not depend on `get_key` and this function
        // staying in sync on bounds checks.
        key.try_into().map_err(|_| VsError::InvalidInput)
    }
}

impl CryptoProvider for RustCryptoProvider {
    fn aes_gcm_encrypt(
        &self,
        key_id: KeyId,
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
        ciphertext_out: &mut [u8],
        tag_out: &mut [u8; 16],
    ) -> Result<(), VsError> {
        self.require_operational()?;
        self.validate_nonce(nonce)?;
        // Check (but do NOT yet record) that the nonce hasn't been used.
        // We must reject duplicates *before* doing crypto, but we only want
        // to permanently consume the nonce after a successful encrypt — if
        // aes-gcm errors, the message wasn't actually sent, so the nonce
        // should still be available for retry.
        self.nonce_tracker.borrow().check_only(nonce)?;

        let key_bytes = self.get_key_32(key_id)?;
        #[allow(deprecated)] // GenericArray 0.x from_slice — fixed when aes-gcm upgrades
        let cipher = Aes256Gcm::new(key_bytes.into());
        let aes_nonce = Nonce::from(*nonce);

        // Copy plaintext into output buffer; AES-GCM encrypts in place.
        if ciphertext_out.len() < plaintext.len() {
            return Err(VsError::InvalidInput);
        }
        ciphertext_out[..plaintext.len()].copy_from_slice(plaintext);
        let buf = &mut ciphertext_out[..plaintext.len()];

        if let Ok(tag) = cipher.encrypt_in_place_detached(&aes_nonce, aad, buf) {
            #[allow(deprecated)] // GenericArray 0.x as_slice
            tag_out.copy_from_slice(tag.as_slice());
            // Only record the nonce *after* a successful encrypt — see
            // comment above.  A concurrent caller cannot race here because
            // `aes_gcm_encrypt` takes `&self` and the `NonceTracker` is
            // wrapped in a `RefCell` that we briefly borrow_mut now.
            self.nonce_tracker.borrow_mut().check_and_record(nonce)?;
            Ok(())
        } else {
            // Zeroize the output buffer to avoid leaking plaintext on failure.
            buf.zeroize();
            Err(VsError::CryptoError)
        }
    }

    fn aes_gcm_decrypt(
        &self,
        key_id: KeyId,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
        plaintext_out: &mut [u8],
    ) -> Result<(), VsError> {
        self.require_operational()?;
        let key_bytes = self.get_key_32(key_id)?;
        #[allow(deprecated)]
        let cipher = Aes256Gcm::new(key_bytes.into());
        let aes_nonce = Nonce::from(*nonce);
        let aes_tag = Tag::from(*tag);

        if plaintext_out.len() < ciphertext.len() {
            return Err(VsError::InvalidInput);
        }
        plaintext_out[..ciphertext.len()].copy_from_slice(ciphertext);
        let buf = &mut plaintext_out[..ciphertext.len()];

        if cipher
            .decrypt_in_place_detached(&aes_nonce, aad, buf, &aes_tag)
            .is_err()
        {
            // Zeroize the output buffer to avoid leaking ciphertext on auth failure.
            buf.zeroize();
            return Err(VsError::CryptoError);
        }

        Ok(())
    }

    fn sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError> {
        self.require_operational()?;
        let result = Sha256::digest(data);
        hash_out.copy_from_slice(&result);
        Ok(())
    }

    fn hmac_sha256(
        &self,
        key_id: KeyId,
        data: &[u8],
        mac_out: &mut [u8; 32],
    ) -> Result<(), VsError> {
        self.require_operational()?;
        let key = self.get_key(key_id)?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| VsError::CryptoError)?;
        mac.update(data);
        let result = mac.finalize();
        mac_out.copy_from_slice(&result.into_bytes());
        Ok(())
    }

    fn ecdh_derive_shared(
        &self,
        private_key_id: KeyId,
        peer_public: &[u8; 65],
        shared_out: &mut [u8; 32],
    ) -> Result<(), VsError> {
        self.require_operational()?;
        // Parse private scalar.
        let scalar_bytes = self.get_key_32(private_key_id)?;
        let secret_key =
            p256::SecretKey::from_bytes(scalar_bytes.into()).map_err(|_| VsError::CryptoError)?;

        // Parse peer's uncompressed SEC1 public key (0x04 || x || y).
        let encoded = EncodedPoint::from_bytes(peer_public).map_err(|_| VsError::InvalidInput)?;
        let peer_point: Option<AffinePoint> = AffinePoint::from_encoded_point(&encoded).into();
        let peer_affine = peer_point.ok_or(VsError::InvalidInput)?;
        let peer_pk = PublicKey::from_affine(peer_affine).map_err(|_| VsError::InvalidInput)?;

        // Perform ECDH: raw x-coordinate of scalar * point.
        let shared_secret =
            p256::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), peer_pk.as_affine());
        // Use HKDF (RFC 5869) to extract a uniform 32-byte shared secret
        // with domain separation, rather than raw SHA-256 on the x-coordinate.
        let raw = shared_secret.raw_secret_bytes();
        // Use a fixed domain-separation salt per RFC 5869 recommendation.
        // A non-null salt improves extraction quality versus raw x-coordinate.
        let hk = Hkdf::<Sha256>::new(Some(b"craton-shield-ecdh-salt-v1"), raw.as_ref());
        hk.expand(b"craton-shield-ecdh-v1", shared_out)
            .map_err(|_| VsError::CryptoError)?;
        Ok(())
    }

    fn sign_p256(
        &self,
        key_id: KeyId,
        digest: &[u8; 32],
        sig_out: &mut [u8; 64],
    ) -> Result<(), VsError> {
        self.require_operational()?;
        let scalar_bytes = self.get_key_32(key_id)?;
        let signing_key =
            SigningKey::from_bytes(scalar_bytes.into()).map_err(|_| VsError::CryptoError)?;

        // RFC 6979 deterministic k — no RNG needed.
        let sig: Signature = ecdsa::signature::Signer::sign(&signing_key, digest);

        // Raw (r || s) encoding, 64 bytes.
        sig_out.copy_from_slice(&sig.to_bytes());
        Ok(())
    }

    fn verify_p256(
        &self,
        pub_key: &[u8; 65],
        digest: &[u8; 32],
        sig: &[u8; 64],
    ) -> Result<bool, VsError> {
        self.require_operational()?;
        // Parse uncompressed SEC1 public key.
        let encoded = EncodedPoint::from_bytes(pub_key).map_err(|_| VsError::InvalidInput)?;
        let verifying_key =
            VerifyingKey::from_encoded_point(&encoded).map_err(|_| VsError::InvalidInput)?;

        // Parse (r || s) signature.
        let signature = Signature::from_slice(sig).map_err(|_| VsError::InvalidInput)?;

        match verifying_key.verify(digest, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), VsError> {
        self.require_operational()?;
        (self.rng_fn)(buf);
        // Detect TRNG failure: all-zero or all-identical output indicates
        // the entropy source is broken, stuck, or uninitialized.
        // The false-positive rate for a working RNG is negligible
        // (1/256^len for all-zero, similar for all-identical).
        if !buf.is_empty() {
            let mut acc: u8 = 0;
            let mut all_same: u8 = 0;
            let first = buf[0];
            for &b in buf.iter() {
                acc |= b;
                all_same |= b ^ first;
            }
            // Reject all-zero output.
            // Also reject all-identical output for buffers > 1 byte, which
            // indicates a stuck TRNG (e.g., always returning 0xFF).
            let is_bad = acc == 0 || (buf.len() > 1 && all_same == 0);
            if is_bad {
                return Err(VsError::CryptoError);
            }
        }
        Ok(())
    }

    fn delete_key(&mut self, key_id: KeyId) -> Result<(), VsError> {
        let idx = key_id.0 as usize;
        if idx >= MAX_KEY_SLOTS {
            return Err(VsError::PolicyViolation);
        }
        self.keys[idx].0.zeroize();
        self.keys[idx].1 = 0;
        Ok(())
    }

    fn generate_key(&mut self, key_id: KeyId, key_type: KeyType) -> Result<(), VsError> {
        let mut material = [0u8; 32];
        match key_type {
            KeyType::EcdsaP256 | KeyType::EcdhP256 => {
                // P-256 private scalars must be in [1, n-1]. Generate random
                // bytes and validate via the p256 crate, retrying on rejection.
                // The probability of a valid scalar is ~1 - 2^-128, so retries
                // are astronomically unlikely with a working RNG.
                const MAX_RETRIES: u32 = 8;
                let mut valid = false;
                for _ in 0..MAX_RETRIES {
                    (self.rng_fn)(&mut material);
                    if p256::SecretKey::from_bytes((&material).into()).is_ok() {
                        valid = true;
                        break;
                    }
                }
                if !valid {
                    material.zeroize();
                    return Err(VsError::CryptoError);
                }
            }
            KeyType::Aes256 | KeyType::HmacSha256 => {
                (self.rng_fn)(&mut material);
            }
        }
        self.set_key(key_id, &material)?;
        material.zeroize();
        Ok(())
    }

    fn hmac_verify(&self, key_id: KeyId, data: &[u8], mac: &[u8; 32]) -> Result<bool, VsError> {
        self.require_operational()?;
        let key = self.get_key(key_id)?;
        let mut hmac_ctx =
            <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| VsError::CryptoError)?;
        hmac_ctx.update(data);
        // Use hmac's own constant-time verify.
        Ok(hmac_ctx.verify_slice(mac).is_ok())
    }

    fn self_test(&self) -> Result<(), VsError> {
        // Temporarily clear the failed flag so self-test can use crypto ops.
        let previous = self.self_test_failed.get();
        self.self_test_failed.set(false);

        let result = self.run_self_test_kats();
        if result.is_err() {
            self.self_test_failed.set(true);
        } else if previous {
            // Only clear permanently on success.
            self.self_test_failed.set(false);
        }
        result
    }

    /// Lighter periodic self-test for runtime health checks.
    ///
    /// Runs only SHA-256 KAT and random_bytes non-zero check, skipping the
    /// expensive ECDSA, ECDH, and AES-GCM KATs. The full test suite runs
    /// on initialization via [`Self::self_test`].
    ///
    /// This takes ~10x less time than the full self-test, making it suitable
    /// for periodic invocation (e.g., every 1000 ticks) to satisfy FIPS 140-3
    /// conditional/periodic self-test requirements without impacting throughput.
    fn periodic_self_test(&self) -> Result<(), VsError> {
        let previous = self.self_test_failed.get();
        self.self_test_failed.set(false);

        let result = self.run_periodic_kats();
        if result.is_err() {
            self.self_test_failed.set(true);
        } else if previous {
            self.self_test_failed.set(false);
        }
        result
    }
}

// Self-test KAT implementation, separated so the flag logic stays clean.
impl RustCryptoProvider {
    fn run_self_test_kats(&self) -> Result<(), VsError> {
        // -- SHA-256 KAT: NIST FIPS 180-4 empty string --
        let mut hash = [0u8; 32];
        self.sha256(b"", &mut hash)?;
        let expected_sha256_empty: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        if !bool::from(hash.ct_eq(&expected_sha256_empty)) {
            return Err(VsError::CryptoError);
        }

        // -- SHA-256 KAT: NIST FIPS 180-4 "abc" --
        self.sha256(b"abc", &mut hash)?;
        let expected_sha256_abc: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        if !bool::from(hash.ct_eq(&expected_sha256_abc)) {
            return Err(VsError::CryptoError);
        }

        // -- SHA-256 determinism --
        let mut hash2 = [0u8; 32];
        self.sha256(b"craton-shield-canary", &mut hash)?;
        self.sha256(b"craton-shield-canary", &mut hash2)?;
        if !bool::from(hash.ct_eq(&hash2)) {
            return Err(VsError::CryptoError);
        }

        // -- AES-256-GCM KAT (NIST SP 800-38D Test Case 16, 256-bit key) --
        // Key: 0000...00 (32 bytes), Nonce: 0000...00 (12 bytes)
        // Plaintext: empty, AAD: empty
        // Expected Tag: 530f8afbc74536b9a963b4f1c4cb738b
        {
            let kat_key = [0u8; 32];
            // We need a mutable ref for set_key, but self_test takes &self.
            // Instead, use the raw RustCrypto primitives directly for the KAT.
            let cipher = Aes256Gcm::new((&kat_key).into());
            let kat_nonce = Nonce::from([0u8; 12]);
            let mut buf = [];
            let tag = cipher
                .encrypt_in_place_detached(&kat_nonce, &[], &mut buf)
                .map_err(|_| VsError::CryptoError)?;
            let expected_tag: [u8; 16] = [
                0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb,
                0x73, 0x8b,
            ];
            if !bool::from(tag[..].ct_eq(&expected_tag)) {
                return Err(VsError::CryptoError);
            }
        }

        // -- HMAC-SHA-256 KAT: RFC 4231 Test Case 2 --
        // Key: "Jefe" (4 bytes)
        // Data: "what do ya want for nothing?"
        // Expected MAC: 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
        {
            let hmac_key = b"Jefe";
            let hmac_data = b"what do ya want for nothing?";
            let mut hmac_ctx =
                <HmacSha256 as Mac>::new_from_slice(hmac_key).map_err(|_| VsError::CryptoError)?;
            hmac_ctx.update(hmac_data);
            let result = hmac_ctx.finalize();
            let mut computed = [0u8; 32];
            computed.copy_from_slice(&result.into_bytes());
            let expected_hmac: [u8; 32] = [
                0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
                0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
                0x64, 0xec, 0x38, 0x43,
            ];
            if !bool::from(computed.ct_eq(&expected_hmac)) {
                return Err(VsError::CryptoError);
            }
        }

        // -- ECDSA P-256 KAT: RFC 6979 deterministic signature (message = "sample") --
        // Private key (d): C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        // Expected r: EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
        // Expected s: F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
        {
            let ecdsa_privkey: [u8; 32] = [
                0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1,
                0xD6, 0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B,
                0x12, 0x0F, 0x67, 0x21,
            ];
            let expected_r: [u8; 32] = [
                0xEF, 0xD4, 0x8B, 0x2A, 0xAC, 0xB6, 0xA8, 0xFD, 0x11, 0x40, 0xDD, 0x9C, 0xD4, 0x5E,
                0x81, 0xD6, 0x9D, 0x2C, 0x87, 0x7B, 0x56, 0xAA, 0xF9, 0x91, 0xC3, 0x4D, 0x0E, 0xA8,
                0x4E, 0xAF, 0x37, 0x16,
            ];
            let expected_s: [u8; 32] = [
                0xF7, 0xCB, 0x1C, 0x94, 0x2D, 0x65, 0x7C, 0x41, 0xD4, 0x36, 0xC7, 0xA1, 0xB6, 0xE2,
                0x9F, 0x65, 0xF3, 0xE9, 0x00, 0xDB, 0xB9, 0xAF, 0xF4, 0x06, 0x4D, 0xC4, 0xAB, 0x2F,
                0x84, 0x3A, 0xCD, 0xA8,
            ];

            let signing_key = SigningKey::from_bytes((&ecdsa_privkey).into())
                .map_err(|_| VsError::CryptoError)?;
            let verifying_key = VerifyingKey::from(&signing_key);

            // RFC 6979 deterministic signing (SHA-256 hash of "sample" is computed internally)
            let sig: Signature = ecdsa::signature::Signer::sign(&signing_key, b"sample");
            let sig_bytes = sig.to_bytes();

            // Compare r (first 32 bytes) and s (last 32 bytes) against expected values
            if !bool::from(sig_bytes[..32].ct_eq(&expected_r)) {
                return Err(VsError::CryptoError);
            }
            if !bool::from(sig_bytes[32..].ct_eq(&expected_s)) {
                return Err(VsError::CryptoError);
            }

            // Verify the signature against the derived public key
            verifying_key
                .verify(b"sample", &sig)
                .map_err(|_| VsError::CryptoError)?;
        }

        // -- ECDH P-256 KAT: NIST CAVP ECC CDH Primitive Test Vector --
        // Source: NIST CAVP ECCDH test vectors for P-256 (Count = 0)
        // Private key (dIUT):
        //   7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534
        // Peer public key (QCAVSx, QCAVSy):
        //   700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287
        //   db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac
        // Expected shared secret (raw x-coordinate, ZIUT):
        //   46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b
        {
            let ecdh_privkey: [u8; 32] = [
                0x7d, 0x7d, 0xc5, 0xf7, 0x1e, 0xb2, 0x9d, 0xda, 0xf8, 0x0d, 0x62, 0x14, 0x63, 0x2e,
                0xea, 0xe0, 0x3d, 0x90, 0x58, 0xaf, 0x1f, 0xb6, 0xd2, 0x2e, 0xd8, 0x0b, 0xad, 0xb6,
                0x2b, 0xc1, 0xa5, 0x34,
            ];
            let peer_pub_x: [u8; 32] = [
                0x70, 0x0c, 0x48, 0xf7, 0x7f, 0x56, 0x58, 0x4c, 0x5c, 0xc6, 0x32, 0xca, 0x65, 0x64,
                0x0d, 0xb9, 0x1b, 0x6b, 0xac, 0xce, 0x3a, 0x4d, 0xf6, 0xb4, 0x2c, 0xe7, 0xcc, 0x83,
                0x88, 0x33, 0xd2, 0x87,
            ];
            let peer_pub_y: [u8; 32] = [
                0xdb, 0x71, 0xe5, 0x09, 0xe3, 0xfd, 0x9b, 0x06, 0x0d, 0xdb, 0x20, 0xba, 0x5c, 0x51,
                0xdc, 0xc5, 0x94, 0x8d, 0x46, 0xfb, 0xf6, 0x40, 0xdf, 0xe0, 0x44, 0x17, 0x82, 0xca,
                0xb8, 0x5f, 0xa4, 0xac,
            ];
            let expected_raw_shared: [u8; 32] = [
                0x46, 0xfc, 0x62, 0x10, 0x64, 0x20, 0xff, 0x01, 0x2e, 0x54, 0xa4, 0x34, 0xfb, 0xdd,
                0x2d, 0x25, 0xcc, 0xc5, 0x85, 0x20, 0x60, 0x56, 0x1e, 0x68, 0x04, 0x0d, 0xd7, 0x77,
                0x89, 0x97, 0xbd, 0x7b,
            ];

            // Build the peer's uncompressed SEC1 public key (0x04 || x || y).
            let mut peer_sec1 = [0u8; 65];
            peer_sec1[0] = 0x04;
            peer_sec1[1..33].copy_from_slice(&peer_pub_x);
            peer_sec1[33..65].copy_from_slice(&peer_pub_y);

            let secret_key = p256::SecretKey::from_bytes((&ecdh_privkey).into())
                .map_err(|_| VsError::CryptoError)?;
            let encoded =
                EncodedPoint::from_bytes(&peer_sec1[..]).map_err(|_| VsError::CryptoError)?;
            let peer_point: Option<AffinePoint> = AffinePoint::from_encoded_point(&encoded).into();
            let peer_affine = peer_point.ok_or(VsError::CryptoError)?;
            let peer_pk = PublicKey::from_affine(peer_affine).map_err(|_| VsError::CryptoError)?;

            // Perform raw ECDH: scalar multiplication yielding shared x-coordinate.
            let shared_secret =
                p256::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), peer_pk.as_affine());
            let raw = shared_secret.raw_secret_bytes();
            let raw_bytes: &[u8] = raw.as_ref();

            // Verify the raw x-coordinate matches the NIST expected value.
            if !bool::from(raw_bytes.ct_eq(&expected_raw_shared)) {
                return Err(VsError::CryptoError);
            }

            // Also verify that HKDF derivation (as used by ecdh_derive_shared) is
            // deterministic by running it twice and comparing.
            let hk = Hkdf::<Sha256>::new(Some(b"craton-shield-ecdh-salt-v1"), raw_bytes);
            let mut derived_a = [0u8; 32];
            hk.expand(b"craton-shield-ecdh-v1", &mut derived_a)
                .map_err(|_| VsError::CryptoError)?;
            let hk2 = Hkdf::<Sha256>::new(Some(b"craton-shield-ecdh-salt-v1"), raw_bytes);
            let mut derived_b = [0u8; 32];
            hk2.expand(b"craton-shield-ecdh-v1", &mut derived_b)
                .map_err(|_| VsError::CryptoError)?;
            if !bool::from(derived_a.ct_eq(&derived_b)) {
                return Err(VsError::CryptoError);
            }
            // Ensure derived key is non-trivial.
            if derived_a == [0u8; 32] {
                return Err(VsError::CryptoError);
            }
        }

        // -- Random bytes non-zero check --
        let mut rnd = [0u8; 32];
        self.random_bytes(&mut rnd)?;
        let mut rnd_acc: u8 = 0;
        for &b in &rnd {
            rnd_acc |= b;
        }
        if rnd_acc == 0 {
            return Err(VsError::CryptoError);
        }

        Ok(())
    }

    /// Lighter periodic KATs: SHA-256 + random_bytes only.
    fn run_periodic_kats(&self) -> Result<(), VsError> {
        // -- SHA-256 KAT: NIST FIPS 180-4 empty string --
        let mut hash = [0u8; 32];
        self.sha256(b"", &mut hash)?;
        let expected_sha256_empty: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        if !bool::from(hash.ct_eq(&expected_sha256_empty)) {
            return Err(VsError::CryptoError);
        }

        // -- Random bytes non-zero check --
        let mut rnd = [0u8; 32];
        self.random_bytes(&mut rnd)?;
        let mut rnd_acc: u8 = 0;
        for &b in &rnd {
            rnd_acc |= b;
        }
        if rnd_acc == 0 {
            return Err(VsError::CryptoError);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    /// Test entropy source using a simple counter (deterministic, test-only).
    fn test_rng(buf: &mut [u8]) {
        use core::sync::atomic::{AtomicU64, Ordering};
        static STATE: AtomicU64 = AtomicU64::new(0x1234_5678_9ABC_DEF0);
        let old = STATE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |mut s| {
                for _ in 0..buf.len() {
                    s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                }
                Some(s)
            })
            .expect("closure always returns Some");
        let mut state = old;
        for b in buf.iter_mut() {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            *b = (state >> 33) as u8;
        }
    }

    fn make_provider() -> RustCryptoProvider {
        RustCryptoProvider::new(test_rng)
    }

    // -- Key management -------------------------------------------------------

    #[test]
    fn set_and_get_key() {
        let mut p = make_provider();
        let key = [0xAA; 32];
        assert!(p.set_key(KeyId(0), &key).is_ok());
        assert_eq!(p.get_key(KeyId(0)).unwrap(), &key);
    }

    #[test]
    fn slot_out_of_range() {
        let mut p = make_provider();
        assert_eq!(
            p.set_key(KeyId(MAX_KEY_SLOTS as u32), &[1; 16]),
            Err(VsError::PolicyViolation)
        );
    }

    #[test]
    fn empty_key_rejected() {
        let mut p = make_provider();
        assert_eq!(p.set_key(KeyId(0), &[]), Err(VsError::InvalidInput));
    }

    #[test]
    fn unprovisioned_slot_returns_not_initialized() {
        let p = make_provider();
        assert_eq!(p.get_key(KeyId(0)), Err(VsError::NotInitialized));
    }

    // -- AES-256-GCM ----------------------------------------------------------

    #[test]
    fn aes_gcm_roundtrip() {
        let mut p = make_provider();
        let key = [0x42; 32];
        p.set_key(KeyId(0), &key).unwrap();

        let plaintext = b"hello craton-shield";
        let aad = b"metadata";
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 1];
        let mut ct = [0u8; 64];
        let mut tag = [0u8; 16];
        p.aes_gcm_encrypt(KeyId(0), &nonce, plaintext, aad, &mut ct, &mut tag)
            .unwrap();

        // Ciphertext differs from plaintext.
        assert_ne!(&ct[..plaintext.len()], plaintext);

        // Decrypt recovers plaintext.
        let mut pt = [0u8; 64];
        p.aes_gcm_decrypt(KeyId(0), &nonce, &ct[..plaintext.len()], aad, &tag, &mut pt)
            .unwrap();
        assert_eq!(&pt[..plaintext.len()], plaintext);
    }

    #[test]
    fn aes_gcm_tampered_tag_fails() {
        let mut p = make_provider();
        p.set_key(KeyId(0), &[0x42; 32]).unwrap();

        let nonce = [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 2];
        let mut ct = [0u8; 16];
        let mut tag = [0u8; 16];
        p.aes_gcm_encrypt(KeyId(0), &nonce, b"secret", &[], &mut ct, &mut tag)
            .unwrap();

        tag[0] ^= 0xFF; // Tamper.
        let mut pt = [0u8; 16];
        assert_eq!(
            p.aes_gcm_decrypt(KeyId(0), &nonce, &ct[..6], &[], &tag, &mut pt),
            Err(VsError::CryptoError)
        );
    }

    #[test]
    fn aes_gcm_wrong_aad_fails() {
        let mut p = make_provider();
        p.set_key(KeyId(0), &[0x42; 32]).unwrap();

        let nonce = [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 3];
        let mut ct = [0u8; 16];
        let mut tag = [0u8; 16];
        p.aes_gcm_encrypt(KeyId(0), &nonce, b"data", b"aad-1", &mut ct, &mut tag)
            .unwrap();

        let mut pt = [0u8; 16];
        assert_eq!(
            p.aes_gcm_decrypt(KeyId(0), &nonce, &ct[..4], b"aad-2", &tag, &mut pt),
            Err(VsError::CryptoError)
        );
    }

    #[test]
    fn aes_gcm_all_zero_nonce_rejected() {
        let mut p = make_provider();
        p.set_key(KeyId(0), &[0x42; 32]).unwrap();

        let nonce = [0u8; 12];
        let mut ct = [0u8; 16];
        let mut tag = [0u8; 16];
        assert_eq!(
            p.aes_gcm_encrypt(KeyId(0), &nonce, b"x", &[], &mut ct, &mut tag),
            Err(VsError::InvalidInput)
        );
    }

    // -- SHA-256 --------------------------------------------------------------

    #[test]
    fn sha256_known_answer() {
        let p = make_provider();
        let mut hash = [0u8; 32];
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        p.sha256(b"", &mut hash).unwrap();
        assert_eq!(
            hash,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }

    #[test]
    fn sha256_deterministic() {
        let p = make_provider();
        let mut h1 = [0u8; 32];
        let mut h2 = [0u8; 32];
        p.sha256(b"craton-shield", &mut h1).unwrap();
        p.sha256(b"craton-shield", &mut h2).unwrap();
        assert_eq!(h1, h2);
    }

    // -- HMAC-SHA-256 ---------------------------------------------------------

    #[test]
    fn hmac_sha256_basic() {
        let mut p = make_provider();
        p.set_key(KeyId(0), &[0xBB; 32]).unwrap();

        let mut mac1 = [0u8; 32];
        let mut mac2 = [0u8; 32];
        p.hmac_sha256(KeyId(0), b"message", &mut mac1).unwrap();
        p.hmac_sha256(KeyId(0), b"message", &mut mac2).unwrap();
        assert_eq!(mac1, mac2); // Deterministic.

        // Different data produces different MAC.
        p.hmac_sha256(KeyId(0), b"other", &mut mac2).unwrap();
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn hmac_different_keys_differ() {
        let mut p = make_provider();
        p.set_key(KeyId(0), &[0xAA; 32]).unwrap();
        p.set_key(KeyId(1), &[0xBB; 32]).unwrap();

        let mut mac_a = [0u8; 32];
        let mut mac_b = [0u8; 32];
        p.hmac_sha256(KeyId(0), b"same", &mut mac_a).unwrap();
        p.hmac_sha256(KeyId(1), b"same", &mut mac_b).unwrap();
        assert_ne!(mac_a, mac_b);
    }

    // -- ECDSA P-256 ----------------------------------------------------------

    #[test]
    fn ecdsa_sign_verify_roundtrip() {
        let mut p = make_provider();

        // Generate a P-256 key pair.
        let key_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let signing_key = SigningKey::from_bytes((&key_bytes).into()).unwrap();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_encoded_point(false);

        // Provision private key.
        p.set_key(KeyId(0), &signing_key.to_bytes()).unwrap();

        // Sign a digest.
        let digest_ga = Sha256::digest(b"test message");
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&digest_ga);
        let mut sig = [0u8; 64];
        p.sign_p256(KeyId(0), &digest, &mut sig).unwrap();

        // Verify with public key.
        let mut pub_key_65 = [0u8; 65];
        pub_key_65.copy_from_slice(pub_bytes.as_bytes());
        let result = p.verify_p256(&pub_key_65, &digest, &sig).unwrap();
        assert!(result);
    }

    #[test]
    fn ecdsa_wrong_digest_fails_verify() {
        let mut p = make_provider();

        let key_bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let signing_key = SigningKey::from_bytes((&key_bytes).into()).unwrap();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_encoded_point(false);
        let mut pub_key_65 = [0u8; 65];
        pub_key_65.copy_from_slice(pub_bytes.as_bytes());

        p.set_key(KeyId(0), &key_bytes).unwrap();

        let digest = [0xAA; 32];
        let mut sig = [0u8; 64];
        p.sign_p256(KeyId(0), &digest, &mut sig).unwrap();

        // Verify with wrong digest.
        let wrong_digest = [0xBB; 32];
        let result = p.verify_p256(&pub_key_65, &wrong_digest, &sig).unwrap();
        assert!(!result);
    }

    // -- ECDH P-256 -----------------------------------------------------------

    #[test]
    fn ecdh_shared_secret_matches() {
        let mut p = make_provider();

        // Two key pairs (Alice and Bob).
        let alice_sk_bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let bob_sk_bytes = [
            0x20, 0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13,
            0x12, 0x11, 0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05,
            0x04, 0x03, 0x02, 0x01,
        ];

        let alice_sk = p256::SecretKey::from_bytes((&alice_sk_bytes).into()).unwrap();
        let bob_sk = p256::SecretKey::from_bytes((&bob_sk_bytes).into()).unwrap();

        let alice_pub = alice_sk.public_key().to_encoded_point(false);
        let bob_pub = bob_sk.public_key().to_encoded_point(false);

        let mut alice_pub_65 = [0u8; 65];
        alice_pub_65.copy_from_slice(alice_pub.as_bytes());
        let mut bob_pub_65 = [0u8; 65];
        bob_pub_65.copy_from_slice(bob_pub.as_bytes());

        p.set_key(KeyId(0), &alice_sk_bytes).unwrap();
        p.set_key(KeyId(1), &bob_sk_bytes).unwrap();

        // Alice computes shared secret with Bob's public key.
        let mut alice_shared = [0u8; 32];
        p.ecdh_derive_shared(KeyId(0), &bob_pub_65, &mut alice_shared)
            .unwrap();

        // Bob computes shared secret with Alice's public key.
        let mut bob_shared = [0u8; 32];
        p.ecdh_derive_shared(KeyId(1), &alice_pub_65, &mut bob_shared)
            .unwrap();

        assert_eq!(alice_shared, bob_shared);
        // Shared secret is non-zero.
        assert_ne!(alice_shared, [0u8; 32]);
    }

    // -- Random bytes ---------------------------------------------------------

    #[test]
    fn random_bytes_fills_buffer() {
        let p = make_provider();
        let mut buf = [0u8; 32];
        p.random_bytes(&mut buf).unwrap();
        // Very unlikely to be all zeros with any reasonable RNG.
        assert_ne!(buf, [0u8; 32]);
    }

    #[test]
    fn random_bytes_rejects_all_zero_rng() {
        let p = RustCryptoProvider::new(|buf: &mut [u8]| {
            for b in buf.iter_mut() {
                *b = 0;
            }
        });
        let mut buf = [0u8; 16];
        assert_eq!(p.random_bytes(&mut buf), Err(VsError::CryptoError));
    }

    #[test]
    fn random_bytes_rejects_all_identical_rng() {
        let p = RustCryptoProvider::new(|buf: &mut [u8]| {
            for b in buf.iter_mut() {
                *b = 0xFF;
            }
        });
        let mut buf = [0u8; 16];
        assert_eq!(p.random_bytes(&mut buf), Err(VsError::CryptoError));
    }

    #[test]
    fn random_bytes_accepts_single_byte_all_same() {
        // For a 1-byte buffer, all-identical is acceptable (can't distinguish
        // from valid output).
        let p = RustCryptoProvider::new(|buf: &mut [u8]| {
            for b in buf.iter_mut() {
                *b = 0x42;
            }
        });
        let mut buf = [0u8; 1];
        assert!(p.random_bytes(&mut buf).is_ok());
    }

    // -- Self-test -------------------------------------------------------------

    #[test]
    fn self_test_passes() {
        let p = make_provider();
        assert!(p.self_test().is_ok());
    }

    // -- Key management: delete and generate -----------------------------------

    #[test]
    fn delete_key_clears_slot() {
        let mut p = make_provider();
        p.set_key(KeyId(0), &[0x42; 32]).unwrap();
        assert!(p.get_key(KeyId(0)).is_ok());

        p.delete_key(KeyId(0)).unwrap();
        assert_eq!(p.get_key(KeyId(0)), Err(VsError::NotInitialized));
    }

    #[test]
    fn delete_key_out_of_range() {
        let mut p = make_provider();
        assert_eq!(
            p.delete_key(KeyId(MAX_KEY_SLOTS as u32)),
            Err(VsError::PolicyViolation)
        );
    }

    #[test]
    fn generate_key_creates_valid_key() {
        let mut p = make_provider();
        p.generate_key(KeyId(0), crate::KeyType::Aes256).unwrap();

        // Key should be 32 bytes and usable.
        let key = p.get_key(KeyId(0)).unwrap();
        assert_eq!(key.len(), 32);
        // Generated key should be non-zero.
        assert_ne!(key, &[0u8; 32]);
    }

    // -- HMAC verify -----------------------------------------------------------

    #[test]
    fn hmac_verify_correct() {
        let mut p = make_provider();
        p.set_key(KeyId(0), &[0xBB; 32]).unwrap();

        let mut mac = [0u8; 32];
        p.hmac_sha256(KeyId(0), b"message", &mut mac).unwrap();
        assert!(p.hmac_verify(KeyId(0), b"message", &mac).unwrap());
    }

    #[test]
    fn hmac_verify_wrong_mac() {
        let mut p = make_provider();
        p.set_key(KeyId(0), &[0xBB; 32]).unwrap();

        let wrong_mac = [0xDE; 32];
        assert!(!p.hmac_verify(KeyId(0), b"message", &wrong_mac).unwrap());
    }

    // -- ECDH uses HKDF -------------------------------------------------------

    #[test]
    fn self_test_passes_with_real_crypto() {
        let crypto = make_provider();
        assert!(
            crypto.self_test().is_ok(),
            "self_test with full KATs must pass"
        );
    }

    #[test]
    fn rng_failure_detection() {
        // A provider with a broken RNG that always returns zeros.
        fn broken_rng(buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = 0;
            }
        }
        let crypto = RustCryptoProvider::new(broken_rng);
        let mut buf = [0u8; 32];
        assert!(
            crypto.random_bytes(&mut buf).is_err(),
            "random_bytes must fail when RNG produces all zeros"
        );
    }

    #[test]
    fn rng_failure_detection_small_buffer() {
        // Verify the all-zero check works for small buffers too (threshold lowered).
        fn broken_rng(buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = 0;
            }
        }
        let crypto = RustCryptoProvider::new(broken_rng);
        let mut buf = [0u8; 4];
        assert!(
            crypto.random_bytes(&mut buf).is_err(),
            "random_bytes must fail for small all-zero buffers"
        );
    }

    #[test]
    fn periodic_self_test_passes() {
        let crypto = make_provider();
        assert!(
            crypto.periodic_self_test().is_ok(),
            "periodic_self_test must pass"
        );
    }

    #[test]
    fn generate_key_ecdsa_produces_valid_p256_scalar() {
        let mut p = make_provider();
        p.generate_key(KeyId(0), crate::KeyType::EcdsaP256).unwrap();
        let key = p.get_key(KeyId(0)).unwrap();
        assert_eq!(key.len(), 32);
        // Verify the generated key is a valid P-256 scalar.
        assert!(
            p256::SecretKey::from_bytes(key.into()).is_ok(),
            "generated ECDSA key must be a valid P-256 scalar"
        );
    }

    #[test]
    fn generate_key_ecdh_produces_valid_p256_scalar() {
        let mut p = make_provider();
        p.generate_key(KeyId(0), crate::KeyType::EcdhP256).unwrap();
        let key = p.get_key(KeyId(0)).unwrap();
        assert!(
            p256::SecretKey::from_bytes(key.into()).is_ok(),
            "generated ECDH key must be a valid P-256 scalar"
        );
    }

    #[test]
    fn nonce_validation_allows_legitimate_counter_nonces() {
        let crypto = make_provider();
        // A nonce with same prefix bytes but varying counter should be accepted.
        // This was previously rejected by the overly-aggressive prefix check.
        let nonce = [
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x00, 0x00, 0x00, 0x01,
        ];
        // Should NOT be rejected — the counter portion differs.
        // Note: all_same check would still fail since byte[8] differs from nonce[0].
        assert!(crypto.validate_nonce(&nonce).is_ok());
    }

    #[test]
    fn ecdh_shared_secret_is_non_trivial() {
        // Verify HKDF produces a non-zero, non-trivially derived secret.
        let mut p = make_provider();
        let sk_bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let sk = p256::SecretKey::from_bytes((&sk_bytes).into()).unwrap();
        let pk = sk.public_key().to_encoded_point(false);
        let mut pk_bytes = [0u8; 65];
        pk_bytes.copy_from_slice(pk.as_bytes());

        // Use a different key for the ECDH.
        let other_sk_bytes = [
            0x20, 0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13,
            0x12, 0x11, 0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05,
            0x04, 0x03, 0x02, 0x01,
        ];
        p.set_key(KeyId(0), &other_sk_bytes).unwrap();

        let mut shared = [0u8; 32];
        p.ecdh_derive_shared(KeyId(0), &pk_bytes, &mut shared)
            .unwrap();
        assert_ne!(shared, [0u8; 32]);
    }

    // -----------------------------------------------------------------------
    // Clone isolation tests
    // -----------------------------------------------------------------------

    #[test]
    fn clone_produces_fresh_nonce_tracker() {
        let mut p = make_provider();
        p.set_key(KeyId(0), &[0xAB; 32]).unwrap();

        // Encrypt with the original — this records a nonce in its tracker.
        let plaintext = b"test";
        let nonce = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];
        let mut ct = [0u8; 4];
        let mut tag = [0u8; 16];
        p.aes_gcm_encrypt(KeyId(0), &nonce, b"", plaintext, &mut ct, &mut tag)
            .unwrap();

        // Clone the provider — clone has fresh NonceTracker AND erased keys.
        let mut cloned = p.clone();

        // Re-provision the same key on the clone.
        cloned.set_key(KeyId(0), &[0xAB; 32]).unwrap();

        // The SAME nonce should succeed on the clone because its tracker is fresh.
        // This verifies clone isolation (independent nonce tracking).
        let mut ct2 = [0u8; 4];
        let mut tag2 = [0u8; 16];
        let result = cloned.aes_gcm_encrypt(KeyId(0), &nonce, b"", plaintext, &mut ct2, &mut tag2);
        assert!(result.is_ok(), "clone should have fresh nonce tracker");
    }

    #[test]
    fn clone_propagates_self_test_failure() {
        let p = make_provider();
        // Manually set self_test_failed.
        p.self_test_failed.set(true);
        let cloned = p.clone();
        assert!(
            cloned.self_test_failed.get(),
            "clone must propagate self-test failure"
        );
    }

    #[test]
    fn clone_erases_key_material() {
        let mut p = make_provider();
        p.set_key(KeyId(0), &[0xAB; 32]).unwrap();
        let cloned = p.clone();

        // Clone must NOT have key material — operations should fail with
        // NotInitialized, preventing accidental dual-encryption with the
        // same key (which would cause catastrophic AES-GCM nonce reuse).
        let mut hash = [0u8; 32];
        let result = cloned.hmac_sha256(KeyId(0), b"test", &mut hash);
        assert_eq!(
            result,
            Err(VsError::NotInitialized),
            "clone must erase keys"
        );
    }

    #[test]
    fn clone_can_be_reprovisioned() {
        let mut p = make_provider();
        p.set_key(KeyId(0), &[0xAB; 32]).unwrap();
        let mut cloned = p.clone();

        // Re-provision a different key on the clone.
        cloned.set_key(KeyId(0), &[0xCD; 32]).unwrap();
        let mut hash = [0u8; 32];
        cloned.hmac_sha256(KeyId(0), b"test", &mut hash).unwrap();
        // Should succeed with the new key.
        assert_ne!(hash, [0u8; 32]);
    }
}
