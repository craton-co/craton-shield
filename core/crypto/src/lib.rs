// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Cryptographic provider trait definitions for `Craton Shield`.
//!
//! This crate provides the [`CryptoProvider`] and [`PostQuantumProvider`] trait
//! definitions and the [`KeyId`] type.
//!
//! # Implementations
//!
//! | Provider | Feature | Use |
//! |:---|:---|:---|
//! | `RustCryptoProvider` | `software` | Production software crypto (AES-GCM, ECDSA, ECDH via RustCrypto) |
//! | `RustCryptoPqProvider` | `pq` | **Recommended for v1.0** post-quantum provider (ML-KEM-768 + ML-DSA-65) |
//! | `SoftwareCryptoProvider` | `mock-hsm` | **Test-only** deterministic stubs (not cryptographically secure) |
//!
//! For hardware-backed providers (PKCS#11 HSM, TPM 2.0), see
//! [Craton Shield Enterprise](https://github.com/craton-co/craton-shield-enterprise).
//!
//! # Post-quantum cryptography (`pq` feature) — recommended for v1.0
//!
//! Starting with Craton Shield v1.0, the `pq` Cargo feature is the
//! **recommended default for production deployments**.  It enables the
//! `RustCryptoPqProvider` which implements:
//!
//! - **ML-KEM-768** (FIPS 203, Aug 2024) — key encapsulation, used for
//!   establishing a post-quantum-secure shared secret with a peer.
//! - **ML-DSA-65** (FIPS 204, Aug 2024) — digital signatures, used for
//!   authenticating firmware images, OTA bundles, and policy artifacts.
//!
//! The feature is still gated (rather than enabled-by-default) so that
//! deeply memory-constrained embedded targets — where the ~150 KB code
//! footprint and ~20 KB of stack-resident polynomial state is prohibitive —
//! can still build a classical-only Craton Shield.  For everything else
//! (gateways, ECUs, industrial controllers, server-side relays) the `pq`
//! feature SHOULD be enabled to be quantum-safe ahead of the deprecation
//! of classical KEX/signatures.
//!
//! Enable it in `Cargo.toml`:
//!
//! ```toml
//! vs-crypto = { version = "0.7", features = ["pq", "software"] }
//! ```
//!
//! Both `ml-kem` and `ml-dsa` upstream crate versions are pinned tightly
//! (`=`-prefix in `Cargo.toml`) because the PQC crate APIs and encoded
//! sizes are still in flux.  See the version-pin policy at the top of
//! `src/pq.rs` for the rationale and the upgrade checklist.

// ---------------------------------------------------------------------------
// F-04: Defence-in-depth guards against insecure features in production builds.
//
// The `compile_error!` guards below fire when `debug_assertions` is disabled
// outside of test builds.  However, `debug_assertions` is an LLVM flag that
// can be independently controlled (e.g., `[profile.dev]
// debug-assertions = false` disables it even in dev builds).  To guard
// against that bypass vector we add a complementary runtime check exported
// as `vs_crypto_assert_not_mock()`, which is called from `vs_platform_init`
// in the FFI layer.
// ---------------------------------------------------------------------------

// Compile-time guard: `mock-hsm` must not ship in non-test release builds.
#[cfg(all(feature = "mock-hsm", not(test), not(debug_assertions)))]
compile_error!(
    "The `mock-hsm` feature must not be used in release builds. \
     It provides cryptographically insecure stub implementations \
     intended only for testing. \
     (F-04: also guarded at runtime by `vs_crypto_assert_not_mock`.)"
);

// Compile-time guard: `pq-software` must not ship in non-test release builds.
// CERT NOTE (F-10): ML-KEM-768 and ML-DSA-65 are defined in NIST FIPS 203/204
// (final, Aug 2024) but are not yet included in any FIPS 140-3 validated
// module list as of 2026-04.  For FIPS-validated operation this feature MUST
// remain disabled.  The guard below enforces this at build time.
#[cfg(all(feature = "pq-software", not(test), not(debug_assertions)))]
compile_error!(
    "The `pq-software` feature must not be used in release builds. \
     It provides post-quantum implementations that are NOT FIPS-validated. \
     CERT NOTE: ML-KEM-768/ML-DSA-65 are not on the FIPS 140-3 CMVP approved \
     algorithm list as of 2026-04. Disable this feature for certified builds."
);

/// Runtime guard: returns `true` if the mock-hsm or pq-software insecure
/// features are compiled in, `false` in a clean production build.
///
/// The FFI layer calls this during `vs_platform_init` to provide a
/// belt-and-suspenders defence against the `debug_assertions` bypass
/// described in audit finding F-04.
pub const fn is_insecure_build() -> bool {
    cfg!(feature = "mock-hsm") || cfg!(feature = "pq-software")
}

#[cfg(feature = "software")]
mod software;
#[cfg(feature = "software")]
/// Re-export of the production software [`CryptoProvider`] backed by
/// RustCrypto (AES-GCM, ECDSA P-256, ECDH P-256, SHA-256, HMAC).
pub use software::RustCryptoProvider;

#[cfg(feature = "pq")]
mod pq;
#[cfg(feature = "pq")]
/// Re-export of the production post-quantum provider implementing
/// ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204).
pub use pq::RustCryptoPqProvider;

use subtle::ConstantTimeEq;
use vs_types::VsError;

/// Re-export the `KeyId` newtype from `vs-types`.
pub use vs_types::KeyId;

/// Key type for key generation operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// AES-256 symmetric key (32 bytes).
    Aes256,
    /// HMAC-SHA-256 key (32 bytes).
    HmacSha256,
    /// ECDSA P-256 signing key (32-byte scalar).
    EcdsaP256,
    /// ECDH P-256 key agreement key (32-byte scalar).
    EcdhP256,
}

/// Trait abstracting all cryptographic operations.
///
/// Implementations may target software (`RustCrypto`) or hardware (HSM/TPM).
/// See the enterprise repository for production-ready implementations.
pub trait CryptoProvider {
    /// Encrypt `plaintext` with AES-256-GCM under the key in `key_id`.
    ///
    /// Writes the ciphertext to `ciphertext_out` (which must be at least
    /// `plaintext.len()` bytes) and the 16-byte authentication tag to
    /// `tag_out`.  The nonce is checked for accidental reuse where the
    /// implementation supports it; see `NonceTracker`.
    fn aes_gcm_encrypt(
        &self,
        key_id: KeyId,
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
        ciphertext_out: &mut [u8],
        tag_out: &mut [u8; 16],
    ) -> Result<(), VsError>;

    /// Decrypt `ciphertext` with AES-256-GCM under the key in `key_id`.
    ///
    /// Verifies the 16-byte authentication `tag`.  Returns
    /// `VsError::CryptoError` if the tag does not authenticate.
    fn aes_gcm_decrypt(
        &self,
        key_id: KeyId,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
        plaintext_out: &mut [u8],
    ) -> Result<(), VsError>;

    /// Compute the SHA-256 digest of `data` into `hash_out`.
    fn sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError>;

    /// Compute the HMAC-SHA-256 of `data` under the key in `key_id`.
    fn hmac_sha256(
        &self,
        key_id: KeyId,
        data: &[u8],
        mac_out: &mut [u8; 32],
    ) -> Result<(), VsError>;

    /// Derive an ECDH P-256 shared secret between the local private key in
    /// `private_key_id` and the peer's SEC1-encoded uncompressed public
    /// key bytes `peer_public`.
    fn ecdh_derive_shared(
        &self,
        private_key_id: KeyId,
        peer_public: &[u8; 65],
        shared_out: &mut [u8; 32],
    ) -> Result<(), VsError>;

    /// Sign `digest` (already-hashed) with ECDSA P-256 using the key in
    /// `key_id`.  Writes a raw r||s 64-byte signature to `sig_out`.
    fn sign_p256(
        &self,
        key_id: KeyId,
        digest: &[u8; 32],
        sig_out: &mut [u8; 64],
    ) -> Result<(), VsError>;

    /// Verify an ECDSA P-256 signature.
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if the
    /// signature is cryptographically invalid (wrong key, wrong message, or
    /// tampered bytes), and `Err(_)` only for operational failures (e.g.,
    /// malformed public key bytes or provider degraded).
    ///
    /// # Warning — result must be checked
    ///
    /// This method returns `Ok(false)` — not `Err` — for an invalid signature.
    /// Code that only checks `verify_p256(...)?` (using the `?` operator to
    /// propagate errors) will silently treat an invalid signature as success.
    /// Always inspect the returned `bool`:
    ///
    /// ```ignore
    /// if !crypto.verify_p256(&pub_key, &digest, &sig)? {
    ///     return Err(VsError::AuthenticationFailure);
    /// }
    /// ```
    #[must_use = "Ok(false) means the signature is INVALID; ignoring this return value accepts forged signatures"]
    fn verify_p256(
        &self,
        pub_key: &[u8; 65],
        digest: &[u8; 32],
        sig: &[u8; 64],
    ) -> Result<bool, VsError>;

    /// Fill `buf` with cryptographically-secure random bytes from the
    /// provider's entropy source.
    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), VsError>;

    /// Delete key material from the given slot, zeroizing it.
    ///
    /// After deletion, attempts to use the slot return `NotInitialized`.
    fn delete_key(&mut self, key_id: KeyId) -> Result<(), VsError>;

    /// Generate a fresh random key and store it in the given slot.
    ///
    /// The key type determines the length and intended usage:
    /// - `Aes256` / `HmacSha256` / `EcdsaP256` / `EcdhP256`: 32-byte random key.
    fn generate_key(&mut self, key_id: KeyId, key_type: KeyType) -> Result<(), VsError>;

    /// Compute and verify an HMAC-SHA-256 tag in constant time.
    ///
    /// Returns `Ok(true)` if the MAC matches, `Ok(false)` if the MAC is wrong,
    /// and `Err(_)` only for operational failures (key not found, provider
    /// degraded). The comparison is constant-time via [`subtle::ConstantTimeEq`].
    ///
    /// # Warning — result must be checked
    ///
    /// Like [`verify_p256`](Self::verify_p256), a wrong MAC returns `Ok(false)`,
    /// not `Err`. Always inspect the `bool` value explicitly.
    #[must_use = "Ok(false) means the MAC is INVALID; ignoring this return value accepts tampered data"]
    fn hmac_verify(&self, key_id: KeyId, data: &[u8], mac: &[u8; 32]) -> Result<bool, VsError> {
        let mut computed = [0u8; 32];
        self.hmac_sha256(key_id, data, &mut computed)?;
        Ok(bool::from(computed.ct_eq(mac)))
    }

    /// Run a self-test to verify the crypto provider is functional.
    ///
    /// # Default implementation
    ///
    /// The trait default performs structural checks only: SHA-256 non-zero
    /// output, determinism, and avalanche (different inputs → different
    /// outputs), plus a random-bytes non-zero check.  These checks catch
    /// obvious breakage (zeroed output, constant output) but do **not**
    /// constitute NIST FIPS Known-Answer Tests.
    ///
    /// # Production override — `RustCryptoProvider`
    ///
    /// `RustCryptoProvider` overrides this method with full NIST / RFC
    /// Known-Answer Tests:
    /// - SHA-256: FIPS 180-4 empty-string and "abc" vectors
    /// - AES-256-GCM: NIST SP 800-38D Test Case 16
    /// - HMAC-SHA-256: RFC 4231 Test Case 2
    /// - ECDSA P-256: RFC 6979 deterministic signature ("sample")
    /// - ECDH P-256: NIST CAVP CDH vector (Count = 0)
    ///
    /// Hardware providers (HSM, TPM) **must** override this method with
    /// equivalent KATs for the algorithm set they implement.
    ///
    /// # Usage
    ///
    /// Called during platform initialization to detect misconfigured or
    /// broken crypto backends before any security-critical operations.
    /// Should also be called periodically via [`Self::periodic_self_test`].
    fn self_test(&self) -> Result<(), VsError> {
        // -- SHA-256 structural tests --
        let mut hash_a = [0u8; 32];
        let mut hash_b = [0u8; 32];
        let mut hash_a2 = [0u8; 32];
        // Test 1: hash is non-zero
        self.sha256(b"craton-shield-canary", &mut hash_a)?;
        let mut acc: u8 = 0;
        for &b in &hash_a {
            acc |= b;
        }
        if acc == 0 {
            return Err(VsError::CryptoError);
        }
        // Test 2: determinism -- same input produces same output
        self.sha256(b"craton-shield-canary", &mut hash_a2)?;
        let mut diff: u8 = 0;
        for i in 0..32 {
            diff |= hash_a[i] ^ hash_a2[i];
        }
        if diff != 0 {
            return Err(VsError::CryptoError);
        }
        // Test 3: different inputs produce different outputs
        self.sha256(b"craton-shield-verify", &mut hash_b)?;
        let mut same: u8 = 0xFF;
        for i in 0..32 {
            same &= !(hash_a[i] ^ hash_b[i]);
        }
        if same == 0xFF {
            return Err(VsError::CryptoError);
        }

        // -- Random bytes sanity check --
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

    /// Periodic self-test suitable for runtime health checks.
    ///
    /// Runs the same KATs as [`Self::self_test`]. Call this at regular
    /// intervals (e.g., every 1000 ticks or on-demand) to satisfy
    /// FIPS 140-3 conditional/periodic self-test requirements.
    fn periodic_self_test(&self) -> Result<(), VsError> {
        self.self_test()
    }

    /// Validate that a nonce is safe for use.
    /// Returns `InvalidInput` if the nonce is all zeros, wrong length,
    /// or all 12 bytes are identical (degenerate pattern).
    ///
    /// The accumulation loops are constant-time (no data-dependent branches
    /// inside the loop body). The final decisions use [`subtle::ConstantTimeEq`]
    /// so the overall function timing does not leak which check failed.
    ///
    /// **Note:** This does not track cross-invocation nonce reuse.
    /// Callers must use a monotonic counter or TRNG to generate nonces
    /// and persist the counter across reboots via NVS.
    fn validate_nonce(&self, nonce: &[u8]) -> Result<(), VsError> {
        if nonce.len() != 12 {
            return Err(VsError::InvalidInput);
        }
        // Reject all-zero nonce (catastrophic for AES-GCM).
        // Constant-time: OR all bytes together; result is 0 iff all zero.
        let mut acc: u8 = 0;
        for &b in nonce {
            acc |= b;
        }
        // Reject degenerate nonces where all 12 bytes are identical.
        // This catches both all-zero and constant-fill patterns like
        // [0xAA; 12] that would be catastrophic for AES-GCM if reused.
        let mut all_same: u8 = 0;
        for &b in &nonce[1..] {
            all_same |= b ^ nonce[0];
        }
        // Use constant-time comparison for the final decision so
        // an observer cannot distinguish failure reasons via timing.
        let is_all_zero = acc.ct_eq(&0u8);
        let is_all_identical = all_same.ct_eq(&0u8);
        if bool::from(is_all_zero | is_all_identical) {
            return Err(VsError::InvalidInput);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Post-Quantum Cryptography
// ---------------------------------------------------------------------------

/// ML-KEM (Kyber) ciphertext size for ML-KEM-768.
pub const MLKEM768_CIPHERTEXT_LEN: usize = 1088;

/// ML-KEM shared secret size.
pub const MLKEM_SHARED_SECRET_LEN: usize = 32;

/// ML-DSA (Dilithium) signature size for ML-DSA-65.
pub const MLDSA65_SIGNATURE_LEN: usize = 3309;

/// ML-DSA-65 public key size (FIPS 204, Table 2).
pub const MLDSA65_PUBLIC_KEY_LEN: usize = 1952;

/// Post-quantum cryptography trait.
///
/// Provides ML-KEM (FIPS 203) key encapsulation and ML-DSA (FIPS 204)
/// digital signatures. Implementations are feature-gated and optional —
/// classical `CryptoProvider` operations remain the primary interface.
///
/// All buffer sizes correspond to the NIST Level 3 parameter sets:
/// - ML-KEM-768 for key encapsulation
/// - ML-DSA-65 for digital signatures
///
/// # Production deployment
///
/// All methods that have default implementations return
/// [`VsError::NotInitialized`] by default.  This means that any
/// implementation that does **not** override a method will return an error
/// at runtime — the compiler will **not** warn you that an override is
/// missing.  When writing a production `PostQuantumProvider`:
///
/// 1. Override every method you intend to use.
/// 2. Call [`pq_self_test`](Self::pq_self_test) during initialisation to
///    verify the overridden methods are functional.
/// 3. The [`StubPostQuantumProvider`] is a zero-size type that provides the
///    correct default behavior for platforms that do not require PQC.
pub trait PostQuantumProvider {
    // -----------------------------------------------------------------------
    // Key provisioning
    //
    // Default implementations return `VsError::NotInitialized` so that the
    // `StubPostQuantumProvider` and any other minimal impl need not override
    // them.  Hardware providers and `RustCryptoPqProvider` override these.
    //
    // ⚠️  Forgetting to override a method is a silent runtime error, not a
    // compile-time error.  See the trait-level documentation above.
    // -----------------------------------------------------------------------

    /// Provision an ML-KEM-768 key slot from a deterministic 64-byte seed
    /// (the d ∥ z byte string defined in FIPS 203).
    ///
    /// The seed must be generated from a TRNG and must be device-unique.
    /// The slot index is taken from `key_id.0`; valid range is
    /// `0 .. KEY_SLOTS`.  Returns `VsError::PolicyViolation` if the slot
    /// index is out of range.
    ///
    /// **Override required for production use.**
    /// Default: returns [`VsError::NotInitialized`].
    fn provision_mlkem_key(&mut self, key_id: KeyId, seed: &[u8; 64]) -> Result<(), VsError> {
        let _ = (key_id, seed);
        Err(VsError::NotInitialized)
    }

    /// Provision an ML-DSA-65 signing key slot from a deterministic 32-byte
    /// seed (ξ in FIPS 204).
    ///
    /// **Override required for production use.**
    /// Default: returns [`VsError::NotInitialized`].
    fn provision_mldsa_key(&mut self, key_id: KeyId, seed: &[u8; 32]) -> Result<(), VsError> {
        let _ = (key_id, seed);
        Err(VsError::NotInitialized)
    }

    // -----------------------------------------------------------------------
    // ML-KEM-768 (key encapsulation, FIPS 203)
    // -----------------------------------------------------------------------

    /// Encapsulate a shared secret using the recipient's ML-KEM-768 public
    /// key stored at `key_id`.
    ///
    /// Writes the ciphertext to `ciphertext_out` and the shared secret to
    /// `shared_secret_out`.
    fn mlkem_encapsulate(
        &self,
        key_id: KeyId,
        ciphertext_out: &mut [u8; MLKEM768_CIPHERTEXT_LEN],
        shared_secret_out: &mut [u8; MLKEM_SHARED_SECRET_LEN],
    ) -> Result<(), VsError>;

    /// Decapsulate a shared secret using the private ML-KEM-768 key
    /// at `key_id`.
    fn mlkem_decapsulate(
        &self,
        key_id: KeyId,
        ciphertext: &[u8; MLKEM768_CIPHERTEXT_LEN],
        shared_secret_out: &mut [u8; MLKEM_SHARED_SECRET_LEN],
    ) -> Result<(), VsError>;

    // -----------------------------------------------------------------------
    // ML-DSA-65 (digital signatures, FIPS 204)
    // -----------------------------------------------------------------------

    /// Sign `message` using the ML-DSA-65 private key at `key_id`.
    /// Writes the 3309-byte signature to `sig_out`.
    fn mldsa_sign(
        &self,
        key_id: KeyId,
        message: &[u8],
        sig_out: &mut [u8; MLDSA65_SIGNATURE_LEN],
    ) -> Result<(), VsError>;

    /// Verify an ML-DSA-65 signature against the given public key.
    ///
    /// `pub_key` is the raw 1952-byte ML-DSA-65 public key bytes.
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid.
    ///
    /// # Warning — result must be checked
    ///
    /// `Ok(false)` means the signature is **invalid**. Do not use `?` alone
    /// to check this result; always inspect the returned `bool`.
    #[must_use = "Ok(false) means the ML-DSA signature is INVALID; ignoring this return value accepts forged signatures"]
    fn mldsa_verify(
        &self,
        pub_key: &[u8; MLDSA65_PUBLIC_KEY_LEN],
        message: &[u8],
        sig: &[u8; MLDSA65_SIGNATURE_LEN],
    ) -> Result<bool, VsError>;

    // -----------------------------------------------------------------------
    // Self-test
    // -----------------------------------------------------------------------

    /// Run a self-test to verify the PQ crypto provider is functional.
    ///
    /// Performs ML-KEM-768 encapsulate/decapsulate and ML-DSA-65 sign/verify
    /// roundtrips with fixed seeds to detect misconfigured or broken PQ
    /// crypto backends.
    ///
    /// Called during platform initialization alongside
    /// [`CryptoProvider::self_test`]. Should also be called periodically.
    ///
    /// Default: returns `Ok(())` (no-op for stub providers).
    fn pq_self_test(&self) -> Result<(), VsError> {
        Ok(())
    }
}

/// **Production stub**: returns [`VsError::NotInitialized`] for all operations.
/// This is intentional — it is used when post-quantum cryptography is not enabled
/// at the platform level. Replace with a post-quantum provider (feature `pq-software`)
/// or a hardware PQ provider to enable PQC operations.
#[derive(Clone, Copy, Default)]
pub struct StubPostQuantumProvider;

impl PostQuantumProvider for StubPostQuantumProvider {
    fn mlkem_encapsulate(
        &self,
        _key_id: KeyId,
        _ciphertext_out: &mut [u8; MLKEM768_CIPHERTEXT_LEN],
        _shared_secret_out: &mut [u8; MLKEM_SHARED_SECRET_LEN],
    ) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }

    fn mlkem_decapsulate(
        &self,
        _key_id: KeyId,
        _ciphertext: &[u8; MLKEM768_CIPHERTEXT_LEN],
        _shared_secret_out: &mut [u8; MLKEM_SHARED_SECRET_LEN],
    ) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }

    fn mldsa_sign(
        &self,
        _key_id: KeyId,
        _message: &[u8],
        _sig_out: &mut [u8; MLDSA65_SIGNATURE_LEN],
    ) -> Result<(), VsError> {
        Err(VsError::NotInitialized)
    }

    fn mldsa_verify(
        &self,
        _pub_key: &[u8; MLDSA65_PUBLIC_KEY_LEN],
        _message: &[u8],
        _sig: &[u8; MLDSA65_SIGNATURE_LEN],
    ) -> Result<bool, VsError> {
        Err(VsError::NotInitialized)
    }
}

// ---------------------------------------------------------------------------
// Software Post-Quantum Provider (mock / test)
// ---------------------------------------------------------------------------

/// Maximum PQ key slots.
#[cfg(any(feature = "pq-software", test))]
const PQ_MAX_KEY_SLOTS: usize = 8;

/// Maximum PQ key material length (ML-DSA-65 public key is 1952 bytes).
#[cfg(any(feature = "pq-software", test))]
const PQ_MAX_KEY_LEN: usize = 2048;

/// Software-only mock post-quantum provider for testing and development.
///
/// **Not for production use.** Implements all `PostQuantumProvider`
/// operations using deterministic algorithms that are *not*
/// cryptographically secure. Feature-gated behind `pq-software` and
/// always available in `#[cfg(test)]` builds.
///
/// # Roadmap to production PQC
///
/// - Integrate `ml-kem` crate for ML-KEM-768 (FIPS 203) key encapsulation.
/// - Integrate `ml-dsa` crate for ML-DSA-65 (FIPS 204) digital signatures.
/// - Add HSM/TPM backend for PQ operations (NXP EdgeLock, Infineon
///   OPTIGA TPM with PQ support).
/// - Implement hybrid classical+PQ scheme per CNSA 2.0 guidance
///   (e.g., ECDH + ML-KEM for key agreement).
/// - Add FIPS 203/204 Known Answer Tests (KATs) for certification.
/// - Benchmark PQ operations on target hardware (S32G3) to validate
///   WCET budgets.
#[cfg(any(feature = "pq-software", test))]
pub struct SoftwarePostQuantumProvider {
    keys: [([u8; PQ_MAX_KEY_LEN], usize); PQ_MAX_KEY_SLOTS],
}

#[cfg(any(feature = "pq-software", test))]
impl Drop for SoftwarePostQuantumProvider {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for slot in &mut self.keys {
            slot.0.zeroize();
            slot.1 = 0;
        }
    }
}

#[cfg(any(feature = "pq-software", test))]
impl Default for SoftwarePostQuantumProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(feature = "pq-software", test))]
impl SoftwarePostQuantumProvider {
    /// Create a new software PQ provider with empty key slots.
    pub fn new() -> Self {
        Self {
            keys: [([0u8; PQ_MAX_KEY_LEN], 0); PQ_MAX_KEY_SLOTS],
        }
    }

    /// Provision PQ key material into a slot.
    pub fn set_key(&mut self, slot: KeyId, material: &[u8]) -> Result<(), VsError> {
        let idx = slot.0 as usize;
        if idx >= PQ_MAX_KEY_SLOTS {
            return Err(VsError::PolicyViolation);
        }
        if material.len() > PQ_MAX_KEY_LEN {
            return Err(VsError::PolicyViolation);
        }
        self.keys[idx].0 = [0u8; PQ_MAX_KEY_LEN];
        self.keys[idx].0[..material.len()].copy_from_slice(material);
        self.keys[idx].1 = material.len();
        Ok(())
    }

    fn get_key(&self, slot: KeyId) -> Result<&[u8], VsError> {
        let idx = slot.0 as usize;
        if idx >= PQ_MAX_KEY_SLOTS || self.keys[idx].1 == 0 {
            return Err(VsError::NotInitialized);
        }
        Ok(&self.keys[idx].0[..self.keys[idx].1])
    }

    /// Deterministic mock hash spread over an output buffer.
    fn mock_hash(data: &[u8], out: &mut [u8]) {
        for b in out.iter_mut() {
            *b = 0;
        }
        for (i, &b) in data.iter().enumerate() {
            let idx = i % out.len();
            out[idx] = out[idx].wrapping_add(b);
            let next = (idx + 1) % out.len();
            out[next] = out[next].wrapping_add(out[idx].wrapping_mul(31));
        }
        for i in 0..out.len() {
            let next = (i + 1) % out.len();
            out[next] ^= out[i].wrapping_mul(17);
        }
    }
}

#[cfg(any(feature = "pq-software", test))]
impl PostQuantumProvider for SoftwarePostQuantumProvider {
    fn mlkem_encapsulate(
        &self,
        key_id: KeyId,
        ciphertext_out: &mut [u8; MLKEM768_CIPHERTEXT_LEN],
        shared_secret_out: &mut [u8; MLKEM_SHARED_SECRET_LEN],
    ) -> Result<(), VsError> {
        let key = self.get_key(key_id)?;
        // Mock: ciphertext = hash(key), shared_secret = hash(key ^ 0xAA)
        Self::mock_hash(key, ciphertext_out);
        let mut flipped = [0u8; PQ_MAX_KEY_LEN];
        let key_len = key.len();
        flipped[..key_len].copy_from_slice(key);
        for b in flipped[..key_len].iter_mut() {
            *b ^= 0xAA;
        }
        Self::mock_hash(&flipped[..key_len], shared_secret_out);
        Ok(())
    }

    fn mlkem_decapsulate(
        &self,
        key_id: KeyId,
        ciphertext: &[u8; MLKEM768_CIPHERTEXT_LEN],
        shared_secret_out: &mut [u8; MLKEM_SHARED_SECRET_LEN],
    ) -> Result<(), VsError> {
        let key = self.get_key(key_id)?;
        // Mock: verify ciphertext matches expected, then derive same secret
        let mut expected_ct = [0u8; MLKEM768_CIPHERTEXT_LEN];
        Self::mock_hash(key, &mut expected_ct);
        if !bool::from(ciphertext.ct_eq(&expected_ct)) {
            return Err(VsError::CryptoError);
        }
        let mut flipped = [0u8; PQ_MAX_KEY_LEN];
        let key_len = key.len();
        flipped[..key_len].copy_from_slice(key);
        for b in flipped[..key_len].iter_mut() {
            *b ^= 0xAA;
        }
        Self::mock_hash(&flipped[..key_len], shared_secret_out);
        Ok(())
    }

    fn mldsa_sign(
        &self,
        key_id: KeyId,
        message: &[u8],
        sig_out: &mut [u8; MLDSA65_SIGNATURE_LEN],
    ) -> Result<(), VsError> {
        let key = self.get_key(key_id)?;
        // Mock: signature = mock_hash(key_hash || message_hash)
        // Two-phase approach: hash key and message separately, then
        // combine to keep stack usage bounded regardless of message size.
        let mut key_hash = [0u8; 32];
        Self::mock_hash(key, &mut key_hash);
        // Hash the full message in chunks to avoid truncation.
        let mut msg_hash = [0u8; 32];
        Self::mock_hash(message, &mut msg_hash);
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&key_hash);
        combined[32..].copy_from_slice(&msg_hash);
        Self::mock_hash(&combined, sig_out);
        Ok(())
    }

    fn mldsa_verify(
        &self,
        pub_key: &[u8; MLDSA65_PUBLIC_KEY_LEN],
        message: &[u8],
        sig: &[u8; MLDSA65_SIGNATURE_LEN],
    ) -> Result<bool, VsError> {
        // Mock: reconstruct expected sig from pub_key and message
        // Same two-phase approach as mldsa_sign.
        let mut key_hash = [0u8; 32];
        Self::mock_hash(pub_key, &mut key_hash);
        let mut msg_hash = [0u8; 32];
        Self::mock_hash(message, &mut msg_hash);
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&key_hash);
        combined[32..].copy_from_slice(&msg_hash);
        let mut expected = [0u8; MLDSA65_SIGNATURE_LEN];
        Self::mock_hash(&combined, &mut expected);
        Ok(sig.ct_eq(&expected).into())
    }
}

// ---------------------------------------------------------------------------
// Nonce management
// ---------------------------------------------------------------------------

/// Monotonic nonce counter for AES-GCM encryption.
///
/// Manages a 12-byte nonce as an 8-byte fixed prefix (typically per-session
/// or per-key) concatenated with a 4-byte big-endian monotonic counter.
/// This guarantees that no nonce is reused for the same prefix, preventing
/// the catastrophic nonce-reuse attack against AES-GCM.
///
/// # Prefix size rationale
///
/// The 8-byte prefix provides a birthday bound of ~2^32 sessions before a
/// 50% collision probability, which is sufficient for automotive ECUs that
/// may reboot frequently over a 15+ year vehicle lifetime (~5,500 reboots
/// per year = ~82,500 total, far below 2^32 = ~4 billion).
///
/// # Key rotation requirement
///
/// The random-prefix mode (`new_random_prefix`) **MUST** be paired with key
/// rotation. If the same AES-GCM key is used indefinitely, prefix collisions
/// across reboots would lead to catastrophic nonce reuse. Rotate keys before
/// the counter space is exhausted or when the key reaches its expiration.
///
/// # Reboot safety
///
/// To prevent nonce reuse across reboots, use [`NonceCounter::new_persisted`]
/// with a starting value loaded from non-volatile storage, or use
/// [`NonceCounter::new_random_prefix`] with a fresh random prefix per boot.
///
/// # Example
///
/// ```ignore
/// let mut nc = NonceCounter::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]).unwrap();
/// let nonce = nc.next()?;  // [0x01, 0x02, ..., 0x08, 0, 0, 0, 1]
/// crypto.aes_gcm_encrypt(key_id, &nonce, plaintext, aad, ct_out, tag_out)?;
/// ```
#[derive(Debug, PartialEq)]
pub struct NonceCounter {
    prefix: [u8; 8],
    counter: u32,
}

impl NonceCounter {
    /// Create a new nonce counter with the given 8-byte prefix.
    ///
    /// The prefix should be unique per key or per session to avoid
    /// cross-context nonce collisions.
    ///
    /// # Nonce reuse warning
    ///
    /// This constructor starts the counter at zero. Callers **must** either:
    /// 1. Persist the counter value via [`Self::counter_for_persistence`] and
    ///    restore it with [`Self::new_persisted`] on reboot, **or**
    /// 2. Rotate to a fresh key on every boot so that nonce reuse across
    ///    power cycles is harmless.
    ///
    /// Failure to do so will cause catastrophic AES-GCM nonce reuse.
    ///
    /// # Errors
    ///
    /// Returns [`VsError::InvalidInput`] if the prefix is all zeros.
    /// An all-zero prefix produces degenerate nonces that will be
    /// rejected by [`CryptoProvider::validate_nonce`]. Use
    /// [`NonceCounter::new_random_prefix`] for safer initialization.
    pub fn new(prefix: [u8; 8]) -> Result<Self, VsError> {
        if !prefix.iter().any(|&b| b != 0) {
            return Err(VsError::InvalidInput);
        }
        Ok(Self { prefix, counter: 0 })
    }

    /// Create a nonce counter restored from persistent storage.
    ///
    /// `persisted_counter` should be the value saved from a prior session.
    /// A safety margin (`REBOOT_SAFETY_MARGIN`) is added to account for
    /// nonces that may have been generated but not yet persisted before
    /// the previous shutdown.
    ///
    /// # Safety guarantee
    ///
    /// By advancing past any nonces that could have been used in the
    /// previous session, this prevents the catastrophic nonce-reuse
    /// attack against AES-GCM across power cycles.
    /// Default reboot safety margin (number of nonces to skip on restore).
    pub const DEFAULT_REBOOT_SAFETY_MARGIN: u32 = 1024;

    /// Create a `NonceCounter` from a persisted counter value, advancing past the
    /// default reboot safety margin so a partially-flushed counter on disk cannot
    /// cause nonce reuse.
    pub fn new_persisted(prefix: [u8; 8], persisted_counter: u32) -> Result<Self, VsError> {
        Self::new_persisted_with_margin(
            prefix,
            persisted_counter,
            Self::DEFAULT_REBOOT_SAFETY_MARGIN,
        )
    }

    /// Create a nonce counter restored from persistent storage with a
    /// custom safety margin.
    ///
    /// `safety_margin` is the number of nonces to skip past the persisted
    /// counter to account for nonces generated but not yet persisted
    /// before shutdown.
    ///
    /// # Errors
    ///
    /// Returns [`VsError::InvalidInput`] if the prefix is all zeros.
    /// Returns [`VsError::ResourceExhausted`] if `persisted_counter + safety_margin`
    /// would overflow `u32::MAX`.
    pub fn new_persisted_with_margin(
        prefix: [u8; 8],
        persisted_counter: u32,
        safety_margin: u32,
    ) -> Result<Self, VsError> {
        if !prefix.iter().any(|&b| b != 0) {
            return Err(VsError::InvalidInput);
        }
        // Use checked_add to detect exhaustion rather than silently saturating.
        let counter = persisted_counter
            .checked_add(safety_margin)
            .ok_or(VsError::ResourceExhausted)?;
        Ok(Self { prefix, counter })
    }

    /// Create a nonce counter with a random prefix, guaranteeing uniqueness
    /// across reboots without requiring persistent storage.
    ///
    /// The caller supplies 8 random bytes (e.g. from the crypto provider's
    /// RNG). Each boot gets a unique prefix, making counter overlap across
    /// boots cryptographically unlikely (birthday bound: ~2^32 boots with
    /// the same key before a 50% collision chance on the 8-byte prefix).
    ///
    /// # Key rotation
    ///
    /// This mode **MUST** be paired with key rotation. If the same key is
    /// used across too many reboots, prefix collisions become likely and
    /// would result in catastrophic AES-GCM nonce reuse.
    ///
    /// # Errors
    ///
    /// Returns [`VsError::InvalidInput`] if the prefix is all zeros,
    /// which indicates a broken RNG. An all-zero prefix produces
    /// degenerate nonces that would be rejected by
    /// [`CryptoProvider::validate_nonce`].
    pub fn new_random_prefix(random_prefix: [u8; 8]) -> Result<Self, VsError> {
        if !random_prefix.iter().any(|&b| b != 0) {
            return Err(VsError::InvalidInput);
        }
        Ok(Self {
            prefix: random_prefix,
            counter: 0,
        })
    }

    /// Return the current counter value (number of nonces generated).
    pub fn count(&self) -> u32 {
        self.counter
    }

    /// Return the counter value for persistence to non-volatile storage.
    ///
    /// Callers should periodically save this value so that
    /// [`NonceCounter::new_persisted`] can be used after a reboot.
    pub fn counter_for_persistence(&self) -> u32 {
        self.counter
    }

    // `last_counter_value` was removed in 0.7.0 — use
    // `counter_for_persistence()` (identical functionality, clearer name).

    /// Generate the next unique 12-byte nonce.
    ///
    /// Returns [`VsError::ResourceExhausted`] when the counter reaches
    /// `u32::MAX` (after ~4 billion nonces). Callers should rotate keys
    /// well before this limit.
    pub fn next(&mut self) -> Result<[u8; 12], VsError> {
        let c = self
            .counter
            .checked_add(1)
            .ok_or(VsError::ResourceExhausted)?;
        self.counter = c;
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.prefix);
        nonce[8..].copy_from_slice(&c.to_be_bytes());
        Ok(nonce)
    }
}

impl Drop for NonceCounter {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.prefix.zeroize();
        self.counter = 0;
    }
}

// ---------------------------------------------------------------------------
// Nonce Reuse Tracker
// ---------------------------------------------------------------------------

/// Ring buffer that tracks recently used nonces and rejects duplicates.
///
/// This provides a best-effort defence against accidental nonce reuse
/// within a single session. It stores the last `NONCE_TRACKER_CAPACITY`
/// nonces and checks new nonces against the ring before use.
///
/// # Limitations
///
/// - Only tracks the last N nonces; old nonces fall out of the ring.
/// - Not persisted across reboots (use `NonceCounter` for that).
/// - The `MonotonicCounter` / `NonceCounter` design already prevents
///   counter-based reuse; this catches programming errors where a caller
///   bypasses the counter.
const NONCE_TRACKER_CAPACITY: usize = 256;

/// Rebuild the Bloom filter from the live ring every N evictions.
///
/// Once the ring is saturated, naive Bloom inserts on every record monotonically
/// drive the filter toward all-ones; after ~256 unique nonces every lookup falls
/// through to the constant-time 256-slot scan and the fast path disappears.
///
/// Periodically rebuilding the Bloom from the currently-live ring contents
/// preserves the fast path: bits for evicted nonces are cleared, while bits
/// for live nonces are restored. A cadence of 64 evictions amortises the
/// rebuild (one O(N) sweep per N/4 evictions) and keeps Bloom saturation
/// bounded by roughly `count / NONCE_TRACKER_CAPACITY` between rebuilds.
///
/// Trade-off: shorter cadence → smaller saturation window, more frequent
/// O(N) sweeps. Longer cadence → larger windows of degraded fast-path. 64
/// is a balance between the two on a 256-entry ring.
const BLOOM_REBUILD_INTERVAL: u32 = 64;

/// Tracks recently-used AES-GCM nonces to detect accidental reuse.
///
/// # Capacity and eviction
///
/// The tracker maintains a fixed-size ring buffer of `NONCE_TRACKER_CAPACITY`
/// (256) entries. When full, the oldest entry is evicted to make room for a
/// new nonce. This means a replayed nonce will only be detected if it is
/// reused within the most recent 256 unique nonces. For most automotive
/// session-based protocols this is sufficient, but callers performing very
/// high-throughput encryption should be aware of this window.
///
/// The 12-byte AES-GCM nonce space (2^96) makes accidental collisions
/// astronomically unlikely; this tracker guards against *programmatic* reuse
/// (e.g., counter reset after reboot without persisted state).
///
/// # Bloom filter maintenance
///
/// A 256-bit Bloom filter provides a fast-path skip for unseen nonces. Because
/// the Bloom never sees deletions, naive operation would drive every bit to
/// `1` once enough unique nonces have passed through (~256), reducing every
/// lookup to the constant-time full-ring scan. We mitigate this by rebuilding
/// the Bloom from the live ring contents every `BLOOM_REBUILD_INTERVAL`
/// evictions: an O(NONCE_TRACKER_CAPACITY) sweep that clears bits for evicted
/// nonces while keeping the filter accurate for the currently-tracked set.
#[derive(Clone)]
pub struct NonceTracker {
    ring: [[u8; 12]; NONCE_TRACKER_CAPACITY],
    head: usize,
    count: usize,
    /// Bloom filter (256 bits) for fast-path rejection of unseen nonces.
    ///
    /// When a nonce's Bloom bit is NOT set, the nonce is definitely new and
    /// the expensive constant-time full-ring scan can be skipped. When the
    /// bit IS set, the scan proceeds as before (false positives are harmless).
    ///
    /// This is safe because nonces are not secret — they are transmitted in
    /// cleartext alongside AES-GCM ciphertext. The timing difference between
    /// "Bloom says new" and "Bloom says maybe seen" leaks only whether a
    /// nonce was possibly used before, which is not security-sensitive.
    bloom: [u64; 4],
    /// Number of evictions performed since the last Bloom rebuild.
    ///
    /// Wrapping counter that triggers a rebuild every
    /// `BLOOM_REBUILD_INTERVAL` evictions to bound Bloom saturation.
    evictions_since_rebuild: u32,
    /// Whether this tracker was initialized from persistent storage.
    /// When `false`, `check_and_record` will return an error to remind
    /// callers to load persisted state before encrypting.
    require_persistence_init: bool,
    initialized: bool,
}

impl Default for NonceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceTracker {
    /// Create a new empty tracker.
    ///
    /// The returned tracker does **not** require persistence initialisation,
    /// so existing callers are unaffected. Use
    /// [`new_with_persistence_required`](Self::new_with_persistence_required)
    /// when the tracker must be loaded from persistent storage before use.
    pub const fn new() -> Self {
        Self {
            ring: [[0u8; 12]; NONCE_TRACKER_CAPACITY],
            head: 0,
            count: 0,
            bloom: [0u64; 4],
            evictions_since_rebuild: 0,
            require_persistence_init: false,
            initialized: true,
        }
    }

    /// Create a tracker that **must** be initialised from persistent storage
    /// before it will accept any nonce.
    ///
    /// Until [`mark_initialized`](Self::mark_initialized) is called,
    /// [`check_and_record`](Self::check_and_record) will return
    /// `Err(VsError::NotInitialized)`. This prevents nonce reuse across
    /// reboots by forcing callers to reload persisted nonce state first.
    pub const fn new_with_persistence_required() -> Self {
        Self {
            ring: [[0u8; 12]; NONCE_TRACKER_CAPACITY],
            head: 0,
            count: 0,
            bloom: [0u64; 4],
            evictions_since_rebuild: 0,
            require_persistence_init: true,
            initialized: false,
        }
    }

    /// Mark this tracker as initialised from persistent storage.
    ///
    /// After calling this method, [`check_and_record`](Self::check_and_record)
    /// will operate normally. This should be called once the caller has
    /// restored any previously persisted nonce state (e.g., the last-used
    /// counter or nonce ring) into the tracker.
    pub fn mark_initialized(&mut self) {
        self.initialized = true;
    }

    /// Compute a Bloom filter bit index (0..255) from a nonce using FNV-1a.
    fn bloom_index(nonce: &[u8; 12]) -> u8 {
        let mut h: u32 = 0x811c_9dc5; // FNV offset basis
        for &b in nonce {
            h ^= b as u32;
            h = h.wrapping_mul(0x0100_0193); // FNV prime
        }
        // Fold to 8 bits for 256-bit Bloom filter.
        ((h ^ (h >> 8) ^ (h >> 16) ^ (h >> 24)) & 0xFF) as u8
    }

    /// Test whether a bit is set in the Bloom filter.
    fn bloom_test(&self, idx: u8) -> bool {
        let word = (idx / 64) as usize;
        let bit = idx % 64;
        (self.bloom[word] >> bit) & 1 == 1
    }

    /// Set a bit in the Bloom filter.
    fn bloom_set(&mut self, idx: u8) {
        let word = (idx / 64) as usize;
        let bit = idx % 64;
        self.bloom[word] |= 1u64 << bit;
    }

    /// Rebuild the Bloom filter from the currently-live ring contents.
    ///
    /// Called periodically on eviction to clear bits for nonces that have
    /// rolled out of the ring. Cost is O(NONCE_TRACKER_CAPACITY) bit-sets
    /// (one FNV hash per live slot); amortised to roughly one rebuild per
    /// `BLOOM_REBUILD_INTERVAL` evictions.
    fn rebuild_bloom(&mut self) {
        self.bloom = [0u64; 4];
        let live = self.count;
        // Iterate ALL slots up to count, in arbitrary order — ring layout
        // doesn't affect Bloom membership.
        for i in 0..live {
            let idx = Self::bloom_index(&self.ring[i]);
            let word = (idx / 64) as usize;
            let bit = idx % 64;
            self.bloom[word] |= 1u64 << bit;
        }
    }

    /// Record the insertion at `self.head`, advancing the ring and tracking
    /// evictions. Returns `true` when the just-overwritten slot was occupied
    /// (i.e., this was an eviction).
    fn write_slot(&mut self, nonce: &[u8; 12]) -> bool {
        let evicted = self.count == NONCE_TRACKER_CAPACITY;
        self.ring[self.head] = *nonce;
        self.head = (self.head + 1) % NONCE_TRACKER_CAPACITY;
        if self.count < NONCE_TRACKER_CAPACITY {
            self.count += 1;
        }
        evicted
    }

    /// Bump the eviction counter and rebuild the Bloom when the cadence
    /// is reached.
    fn note_eviction(&mut self) {
        self.evictions_since_rebuild = self.evictions_since_rebuild.wrapping_add(1);
        if self.evictions_since_rebuild >= BLOOM_REBUILD_INTERVAL {
            self.evictions_since_rebuild = 0;
            self.rebuild_bloom();
        }
    }

    /// Check whether `nonce` has been seen recently.
    ///
    /// Returns `Err(VsError::NotInitialized)` if this tracker was created
    /// with [`new_with_persistence_required`](Self::new_with_persistence_required)
    /// and [`mark_initialized`](Self::mark_initialized) has not yet been
    /// called. This guards against nonce reuse after a reboot: the caller
    /// **must** reload persisted nonce state before encrypting.
    ///
    /// Returns `Err(VsError::PolicyViolation)` if the nonce was already
    /// tracked (reuse detected), otherwise records it and returns `Ok(())`.
    #[must_use = "nonce-reuse check result must be propagated to the caller"]
    pub fn check_and_record(&mut self, nonce: &[u8; 12]) -> Result<(), VsError> {
        if self.require_persistence_init && !self.initialized {
            return Err(VsError::NotInitialized);
        }
        let bloom_idx = Self::bloom_index(nonce);
        let maybe_seen = self.bloom_test(bloom_idx);

        if maybe_seen {
            // Bloom filter says "maybe seen" — fall back to constant-time scan.
            //
            // F-03 fix: always iterate the full ring capacity so that the
            // number of iterations is constant (NONCE_TRACKER_CAPACITY), not
            // data-dependent (self.count).  A data-dependent loop bound leaks
            // the current fill level of the ring buffer via timing, which
            // violates the constant-time contract and the FIPS 140-3
            // side-channel resistance requirement.
            //
            // Slots beyond `self.count` hold the zero initialiser [0u8;12].
            // We mask their contribution with a data-dependent `subtle::Choice`
            // so the comparison runs in constant time regardless of fill level.
            let mut found: u8 = 0;
            for i in 0..NONCE_TRACKER_CAPACITY {
                // `active` is 1 for slots that have been written, 0 otherwise.
                // Using `subtle::Choice` prevents the compiler from short-circuiting.
                let active = subtle::Choice::from((i < self.count) as u8);
                let matches = self.ring[i].ct_eq(nonce);
                // Only count the match if the slot is active.
                found |= (matches & active).unwrap_u8();
            }
            // Record the nonce before checking `found` so the write path
            // is independent of the match result.
            let evicted = self.write_slot(nonce);
            if evicted {
                self.note_eviction();
            }
            if found != 0 {
                return Err(VsError::PolicyViolation);
            }
        } else {
            // Bloom filter says "definitely new" — skip the CT scan.
            self.bloom_set(bloom_idx);
            let evicted = self.write_slot(nonce);
            if evicted {
                self.note_eviction();
            }
        }

        Ok(())
    }

    /// Check whether `nonce` has been seen recently, **without** recording it.
    ///
    /// Returns the same errors as [`check_and_record`](Self::check_and_record)
    /// (`NotInitialized` if persistence-required and uninitialised;
    /// `PolicyViolation` if the nonce was already tracked), but does **not**
    /// mutate the tracker.  This is used by `RustCryptoProvider::aes_gcm_encrypt`
    /// so that a failing AEAD encrypt does not permanently consume the nonce.
    /// Callers MUST follow a successful operation with
    /// [`check_and_record`](Self::check_and_record) to actually reserve it.
    #[must_use = "nonce-reuse check result must be propagated to the caller"]
    pub fn check_only(&self, nonce: &[u8; 12]) -> Result<(), VsError> {
        if self.require_persistence_init && !self.initialized {
            return Err(VsError::NotInitialized);
        }
        let bloom_idx = Self::bloom_index(nonce);
        let maybe_seen = self.bloom_test(bloom_idx);
        if !maybe_seen {
            return Ok(());
        }
        // Constant-time scan over the full ring capacity, matching
        // `check_and_record` so timing is independent of fill level.
        let mut found: u8 = 0;
        for i in 0..NONCE_TRACKER_CAPACITY {
            let active = subtle::Choice::from((i < self.count) as u8);
            let matches = self.ring[i].ct_eq(nonce);
            found |= (matches & active).unwrap_u8();
        }
        if found != 0 {
            return Err(VsError::PolicyViolation);
        }
        Ok(())
    }

    /// Return how many unique nonces are currently tracked.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return true if no nonces are tracked.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ---------------------------------------------------------------------------
// Software Crypto Provider (mock-hsm / test)
// ---------------------------------------------------------------------------

/// Maximum number of key slots in the mock software provider.
#[cfg(any(feature = "mock-hsm", test))]
const MOCK_MAX_KEY_SLOTS: usize = 16;

/// Maximum key material length in the mock software provider.
#[cfg(any(feature = "mock-hsm", test))]
const MOCK_MAX_KEY_LEN: usize = 32;

/// A software-only mock crypto provider for testing and development.
///
/// **Not for production use.** This provider implements all `CryptoProvider`
/// operations using simple deterministic algorithms that are *not*
/// cryptographically secure. It is feature-gated behind `mock-hsm` and
/// always available in `#[cfg(test)]` builds.
///
/// # Thread safety
///
/// This type is `Send` but **not `Sync`** due to the internal `RefCell`
/// used for nonce tracking. It must not be shared across threads via
/// `&SoftwareCryptoProvider`. This matches the intended single-threaded
/// embedded usage model.
#[cfg(any(feature = "mock-hsm", test))]
pub struct SoftwareCryptoProvider {
    keys: [([u8; MOCK_MAX_KEY_LEN], usize); MOCK_MAX_KEY_SLOTS],
    rng_fn: fn(&mut [u8]),
    nonce_tracker: core::cell::RefCell<NonceTracker>,
}

// Clone produces a copy with a **fresh** (empty) NonceTracker.
// This prevents nonce reuse across clones: each clone starts with its
// own independent tracker.  Callers that need cross-instance nonce
// tracking must use a shared `&mut` or `Mutex`.
#[cfg(any(feature = "mock-hsm", test))]
impl Clone for SoftwareCryptoProvider {
    fn clone(&self) -> Self {
        Self {
            keys: self.keys,
            rng_fn: self.rng_fn,
            // Fresh tracker ensures clones cannot produce overlapping nonces.
            nonce_tracker: core::cell::RefCell::new(NonceTracker::new()),
        }
    }
}

#[cfg(any(feature = "mock-hsm", test))]
impl core::fmt::Debug for SoftwareCryptoProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SoftwareCryptoProvider")
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

#[cfg(any(feature = "mock-hsm", test))]
impl Drop for SoftwareCryptoProvider {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // Zero all key material on drop to prevent secrets lingering
        // in memory. The `zeroize` crate uses volatile writes that the
        // compiler cannot optimise away.
        for slot in &mut self.keys {
            slot.0.zeroize();
            slot.1 = 0;
        }
        // Zero nonce tracker ring buffer to prevent nonce leakage.
        let tracker = self.nonce_tracker.get_mut();
        for entry in &mut tracker.ring {
            entry.zeroize();
        }
        tracker.head = 0;
        tracker.count = 0;
        tracker.bloom = [0u64; 4];
    }
}

#[cfg(any(feature = "mock-hsm", test))]
impl Default for SoftwareCryptoProvider {
    fn default() -> Self {
        Self::new(default_rng)
    }
}

#[cfg(any(feature = "mock-hsm", test))]
fn default_rng(buf: &mut [u8]) {
    // Deterministic LCG PRNG — NOT secure, test-only.
    //
    // Uses a compare-and-swap loop to atomically reserve a range of PRNG
    // states.  This prevents two concurrent threads from loading the same
    // seed and generating identical "random" bytes (which would cause
    // nonce duplication in AES-GCM tests).
    use core::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0xDEAD_BEEF_CAFE_BABE);

    // Atomically advance the global state by `buf.len()` steps and
    // return the old (pre-advance) value.  Each thread gets a unique
    // starting seed even under contention.
    let old = STATE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |mut s| {
            for _ in 0..buf.len() {
                s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            }
            Some(s)
        })
        .expect("closure always returns Some");

    // Generate bytes from the reserved state range.
    let mut state = old;
    for b in buf.iter_mut() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        *b = (state >> 33) as u8;
    }
}

#[cfg(any(feature = "mock-hsm", test))]
impl SoftwareCryptoProvider {
    /// Create a new software crypto provider with the given RNG function.
    pub fn new(rng: fn(&mut [u8])) -> Self {
        Self {
            keys: [([0u8; MOCK_MAX_KEY_LEN], 0); MOCK_MAX_KEY_SLOTS],
            rng_fn: rng,
            nonce_tracker: core::cell::RefCell::new(NonceTracker::new()),
        }
    }

    /// Provision a key into the given slot.
    pub fn set_key(&mut self, slot: KeyId, material: &[u8]) -> Result<(), VsError> {
        let idx = slot.0 as usize;
        if idx >= MOCK_MAX_KEY_SLOTS {
            return Err(VsError::PolicyViolation);
        }
        if material.is_empty() || material.len() > MOCK_MAX_KEY_LEN {
            return Err(VsError::InvalidInput);
        }
        // Zero the entire buffer first to avoid leaking residual key bytes
        // when a shorter key replaces a longer one.
        self.keys[idx].0 = [0u8; MOCK_MAX_KEY_LEN];
        self.keys[idx].0[..material.len()].copy_from_slice(material);
        self.keys[idx].1 = material.len();
        Ok(())
    }

    fn get_key(&self, slot: KeyId) -> Result<&[u8], VsError> {
        let idx = slot.0 as usize;
        if idx >= MOCK_MAX_KEY_SLOTS || self.keys[idx].1 == 0 {
            return Err(VsError::NotInitialized);
        }
        Ok(&self.keys[idx].0[..self.keys[idx].1])
    }

    /// Compute a mock GCM tag incorporating key, nonce, AAD, and ciphertext.
    /// NOT secure — just ensures different inputs produce different tags so
    /// integration tests remain meaningful.
    fn mock_gcm_tag(
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag_out: &mut [u8; 16],
    ) {
        let mut full = [0u8; 32];
        // Start from key
        for (i, &b) in key.iter().enumerate() {
            full[i % 32] = full[i % 32].wrapping_add(b);
        }
        // Mix nonce
        for (i, &b) in nonce.iter().enumerate() {
            full[(i + 3) % 32] = full[(i + 3) % 32].wrapping_add(b.wrapping_mul(37));
        }
        // Mix AAD
        for (i, &b) in aad.iter().enumerate() {
            full[(i + 7) % 32] ^= b.wrapping_add(full[i % 32]);
        }
        // Mix ciphertext
        for (i, &b) in ciphertext.iter().enumerate() {
            full[(i + 13) % 32] = full[(i + 13) % 32].wrapping_add(b.wrapping_mul(19));
        }
        // Diffuse
        for i in 0..32 {
            let next = (i + 1) % 32;
            full[next] ^= full[i].wrapping_mul(17);
        }
        tag_out.copy_from_slice(&full[..16]);
    }

    /// Simple deterministic hash (NOT secure).
    fn simple_hash(data: &[u8], out: &mut [u8; 32]) {
        *out = [0u8; 32];
        for (i, &b) in data.iter().enumerate() {
            let idx = i % 32;
            out[idx] = out[idx].wrapping_add(b);
            let next = (idx + 1) % 32;
            out[next] = out[next].wrapping_add(out[idx].wrapping_mul(31));
        }
        for i in 0..32 {
            let next = (i + 1) % 32;
            out[next] ^= out[i].wrapping_mul(17);
        }
    }
}

#[cfg(any(feature = "mock-hsm", test))]
impl CryptoProvider for SoftwareCryptoProvider {
    fn aes_gcm_encrypt(
        &self,
        key_id: KeyId,
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
        ciphertext_out: &mut [u8],
        tag_out: &mut [u8; 16],
    ) -> Result<(), VsError> {
        self.validate_nonce(nonce)?;
        self.nonce_tracker.borrow_mut().check_and_record(nonce)?;
        let key = self.get_key(key_id)?;
        // Simple XOR "encryption" — NOT secure.
        for (i, b) in ciphertext_out.iter_mut().enumerate().take(plaintext.len()) {
            *b = plaintext[i] ^ key[i % key.len()];
        }
        // Tag incorporates key, nonce, AAD, and ciphertext so tests can
        // detect nonce reuse, AAD mismatch, and ciphertext tampering.
        Self::mock_gcm_tag(key, nonce, aad, &ciphertext_out[..plaintext.len()], tag_out);
        Ok(())
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
        let key = self.get_key(key_id)?;
        // Verify tag (constant-time comparison via `subtle` crate)
        let mut expected_tag = [0u8; 16];
        Self::mock_gcm_tag(key, nonce, aad, ciphertext, &mut expected_tag);
        if tag.ct_eq(&expected_tag).into() {
            // Tag matches — proceed to decrypt.
        } else {
            return Err(VsError::CryptoError);
        }
        // Decrypt (same XOR)
        for (i, b) in plaintext_out.iter_mut().enumerate().take(ciphertext.len()) {
            *b = ciphertext[i] ^ key[i % key.len()];
        }
        Ok(())
    }

    fn sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError> {
        Self::simple_hash(data, hash_out);
        Ok(())
    }

    fn hmac_sha256(
        &self,
        key_id: KeyId,
        data: &[u8],
        mac_out: &mut [u8; 32],
    ) -> Result<(), VsError> {
        let key = self.get_key(key_id)?;
        // Hash(key || data) — uses the full key so different keys produce
        // different MACs, enabling tests for key-rotation and multi-tenant
        // isolation.
        let mut buf = [0u8; 32];
        Self::simple_hash(key, &mut buf);
        // Mix keyed hash with data hash
        let mut data_hash = [0u8; 32];
        Self::simple_hash(data, &mut data_hash);
        for i in 0..32 {
            mac_out[i] = buf[i].wrapping_add(data_hash[i]).wrapping_mul(31);
        }
        // Final diffusion pass
        for i in 0..32 {
            let next = (i + 1) % 32;
            mac_out[next] ^= mac_out[i].wrapping_mul(17);
        }
        Ok(())
    }

    fn ecdh_derive_shared(
        &self,
        private_key_id: KeyId,
        peer_public: &[u8; 65],
        shared_out: &mut [u8; 32],
    ) -> Result<(), VsError> {
        let key = self.get_key(private_key_id)?;
        // Mix private key material and peer public key so different key
        // pairs yield different shared secrets in tests.
        let mut buf = [0u8; 97]; // 32 key + 65 peer
        buf[..key.len()].copy_from_slice(key);
        buf[32..].copy_from_slice(peer_public);
        Self::simple_hash(&buf, shared_out);
        Ok(())
    }

    fn sign_p256(
        &self,
        key_id: KeyId,
        digest: &[u8; 32],
        sig_out: &mut [u8; 64],
    ) -> Result<(), VsError> {
        let key = self.get_key(key_id)?;
        // Deterministic mock signature: hash(key || digest) spread over 64 bytes.
        let mut combined = [0u8; 64]; // key (up to 32) + digest (32)
        combined[..key.len()].copy_from_slice(key);
        combined[32..].copy_from_slice(digest);
        let mut h = [0u8; 32];
        Self::simple_hash(&combined, &mut h);
        sig_out[..32].copy_from_slice(&h);
        // Second half: re-hash with a domain separator
        combined[0] ^= 0xFF;
        Self::simple_hash(&combined, &mut h);
        sig_out[32..].copy_from_slice(&h);
        Ok(())
    }

    fn verify_p256(
        &self,
        pub_key: &[u8; 65],
        digest: &[u8; 32],
        sig: &[u8; 64],
    ) -> Result<bool, VsError> {
        // Reconstruct expected signature using public key bytes [1..33] as the
        // "key material", mirroring sign_p256's structure so that callers who
        // provision the same bytes for both the private slot and public key
        // get a passing round-trip.
        let key = &pub_key[1..33];
        let mut combined = [0u8; 64];
        combined[..key.len()].copy_from_slice(key);
        combined[32..].copy_from_slice(digest);
        let mut expected = [0u8; 64];
        let mut h = [0u8; 32];
        Self::simple_hash(&combined, &mut h);
        expected[..32].copy_from_slice(&h);
        combined[0] ^= 0xFF;
        Self::simple_hash(&combined, &mut h);
        expected[32..].copy_from_slice(&h);
        // Constant-time comparison via `subtle` crate
        Ok(sig.ct_eq(&expected).into())
    }

    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), VsError> {
        (self.rng_fn)(buf);
        Ok(())
    }

    fn delete_key(&mut self, key_id: KeyId) -> Result<(), VsError> {
        use zeroize::Zeroize;
        let idx = key_id.0 as usize;
        if idx >= MOCK_MAX_KEY_SLOTS {
            return Err(VsError::PolicyViolation);
        }
        self.keys[idx].0.zeroize();
        self.keys[idx].1 = 0;
        Ok(())
    }

    fn generate_key(&mut self, key_id: KeyId, _key_type: KeyType) -> Result<(), VsError> {
        use zeroize::Zeroize;
        let mut material = [0u8; 32];
        (self.rng_fn)(&mut material);
        self.set_key(key_id, &material)?;
        material.zeroize();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Stub PQ provider tests
    // -----------------------------------------------------------------------

    #[test]
    fn stub_pq_provider_returns_not_initialized() {
        let pq = StubPostQuantumProvider;
        let mut ct = [0u8; MLKEM768_CIPHERTEXT_LEN];
        let mut ss = [0u8; MLKEM_SHARED_SECRET_LEN];
        assert_eq!(
            pq.mlkem_encapsulate(KeyId(0), &mut ct, &mut ss),
            Err(VsError::NotInitialized)
        );
        assert_eq!(
            pq.mlkem_decapsulate(KeyId(0), &ct, &mut ss),
            Err(VsError::NotInitialized)
        );

        let mut sig = [0u8; MLDSA65_SIGNATURE_LEN];
        assert_eq!(
            pq.mldsa_sign(KeyId(0), b"test", &mut sig),
            Err(VsError::NotInitialized)
        );
        assert_eq!(
            pq.mldsa_verify(&[0u8; MLDSA65_PUBLIC_KEY_LEN], b"test", &sig),
            Err(VsError::NotInitialized)
        );
    }

    #[test]
    fn pq_constant_sizes() {
        assert_eq!(MLKEM768_CIPHERTEXT_LEN, 1088);
        assert_eq!(MLKEM_SHARED_SECRET_LEN, 32);
        assert_eq!(MLDSA65_SIGNATURE_LEN, 3309);
    }

    #[test]
    fn stub_pq_encapsulate_different_key_ids_all_fail() {
        let pq = StubPostQuantumProvider;
        for key_id in [KeyId(0), KeyId(1), KeyId(u32::MAX)] {
            let mut ct = [0u8; MLKEM768_CIPHERTEXT_LEN];
            let mut ss = [0u8; MLKEM_SHARED_SECRET_LEN];
            assert_eq!(
                pq.mlkem_encapsulate(key_id, &mut ct, &mut ss),
                Err(VsError::NotInitialized)
            );
        }
    }

    #[test]
    fn stub_pq_sign_empty_message() {
        let pq = StubPostQuantumProvider;
        let mut sig = [0u8; MLDSA65_SIGNATURE_LEN];
        assert_eq!(
            pq.mldsa_sign(KeyId(0), b"", &mut sig),
            Err(VsError::NotInitialized)
        );
    }

    #[test]
    fn stub_pq_verify_empty_pub_key_and_message() {
        let pq = StubPostQuantumProvider;
        let sig = [0u8; MLDSA65_SIGNATURE_LEN];
        assert_eq!(
            pq.mldsa_verify(&[0u8; MLDSA65_PUBLIC_KEY_LEN], b"", &sig),
            Err(VsError::NotInitialized)
        );
    }

    #[test]
    fn stub_pq_decapsulate_with_zeroed_ciphertext() {
        let pq = StubPostQuantumProvider;
        let ct = [0u8; MLKEM768_CIPHERTEXT_LEN];
        let mut ss = [0u8; MLKEM_SHARED_SECRET_LEN];
        assert_eq!(
            pq.mlkem_decapsulate(KeyId(0), &ct, &mut ss),
            Err(VsError::NotInitialized)
        );
    }

    #[test]
    fn pq_constant_sizes_are_nonzero() {
        let ct_len = MLKEM768_CIPHERTEXT_LEN;
        let ss_len = MLKEM_SHARED_SECRET_LEN;
        let sig_len = MLDSA65_SIGNATURE_LEN;
        assert!(ct_len > 0);
        assert!(ss_len > 0);
        assert!(sig_len > 0);
        assert!(ct_len > ss_len);
    }

    // -----------------------------------------------------------------------
    // PQ size assertion tests (FIPS spec compliance)
    // -----------------------------------------------------------------------

    #[test]
    fn pq_mlkem768_ciphertext_matches_fips_203() {
        assert_eq!(MLKEM768_CIPHERTEXT_LEN, 1088);
    }

    #[test]
    fn pq_mlkem_shared_secret_is_32_bytes() {
        assert_eq!(MLKEM_SHARED_SECRET_LEN, 32);
    }

    #[test]
    fn pq_mldsa65_signature_matches_fips_204() {
        assert_eq!(MLDSA65_SIGNATURE_LEN, 3309);
    }

    #[test]
    fn pq_mldsa65_public_key_matches_fips_204() {
        assert_eq!(MLDSA65_PUBLIC_KEY_LEN, 1952);
    }

    #[test]
    fn pq_stub_provider_is_zero_sized() {
        assert_eq!(
            core::mem::size_of::<StubPostQuantumProvider>(),
            0,
            "StubPostQuantumProvider should be a ZST"
        );
    }

    #[test]
    fn pq_ciphertext_larger_than_shared_secret() {
        let ct = MLKEM768_CIPHERTEXT_LEN;
        let ss = MLKEM_SHARED_SECRET_LEN;
        let sig = MLDSA65_SIGNATURE_LEN;
        assert!(
            ct > ss,
            "ciphertext ({ct}) must exceed shared secret ({ss})"
        );
        assert!(
            sig > ss,
            "signature ({sig}) must exceed shared secret ({ss})"
        );
    }

    // -----------------------------------------------------------------------
    // Software PQ provider tests
    // -----------------------------------------------------------------------

    #[test]
    fn software_pq_encapsulate_decapsulate_roundtrip() {
        let mut pq = SoftwarePostQuantumProvider::new();
        let key_material = [0x42u8; 32];
        pq.set_key(KeyId(0), &key_material).unwrap();

        let mut ct = [0u8; MLKEM768_CIPHERTEXT_LEN];
        let mut ss_enc = [0u8; MLKEM_SHARED_SECRET_LEN];
        pq.mlkem_encapsulate(KeyId(0), &mut ct, &mut ss_enc)
            .unwrap();

        let mut ss_dec = [0u8; MLKEM_SHARED_SECRET_LEN];
        pq.mlkem_decapsulate(KeyId(0), &ct, &mut ss_dec).unwrap();

        assert_eq!(ss_enc, ss_dec, "shared secrets must match after roundtrip");
    }

    #[test]
    fn software_pq_decapsulate_wrong_ciphertext_fails() {
        let mut pq = SoftwarePostQuantumProvider::new();
        pq.set_key(KeyId(0), &[0x42u8; 32]).unwrap();

        let bad_ct = [0xFFu8; MLKEM768_CIPHERTEXT_LEN];
        let mut ss = [0u8; MLKEM_SHARED_SECRET_LEN];
        assert_eq!(
            pq.mlkem_decapsulate(KeyId(0), &bad_ct, &mut ss),
            Err(VsError::CryptoError)
        );
    }

    #[test]
    fn software_pq_sign_verify_roundtrip() {
        let mut pq = SoftwarePostQuantumProvider::new();
        // Use a MLDSA65_PUBLIC_KEY_LEN-sized key so sign and verify
        // use the same bytes (sign hashes key||msg, verify hashes pub_key||msg).
        let key_material = [0x55u8; MLDSA65_PUBLIC_KEY_LEN];
        pq.set_key(KeyId(0), &key_material).unwrap();

        let message = b"test message for signing";
        let mut sig = [0u8; MLDSA65_SIGNATURE_LEN];
        pq.mldsa_sign(KeyId(0), message, &mut sig).unwrap();

        // verify uses the full pub_key directly
        let valid = pq.mldsa_verify(&key_material, message, &sig).unwrap();
        assert!(valid, "signature must verify with matching key");
    }

    #[test]
    fn software_pq_verify_wrong_message_fails() {
        let mut pq = SoftwarePostQuantumProvider::new();
        let key_material = [0x55u8; MLDSA65_PUBLIC_KEY_LEN];
        pq.set_key(KeyId(0), &key_material).unwrap();

        let mut sig = [0u8; MLDSA65_SIGNATURE_LEN];
        pq.mldsa_sign(KeyId(0), b"original", &mut sig).unwrap();

        let valid = pq.mldsa_verify(&key_material, b"tampered", &sig).unwrap();
        assert!(!valid, "signature must not verify with different message");
    }

    #[test]
    fn software_pq_no_key_returns_not_initialized() {
        let pq = SoftwarePostQuantumProvider::new();
        let mut ct = [0u8; MLKEM768_CIPHERTEXT_LEN];
        let mut ss = [0u8; MLKEM_SHARED_SECRET_LEN];
        assert_eq!(
            pq.mlkem_encapsulate(KeyId(0), &mut ct, &mut ss),
            Err(VsError::NotInitialized)
        );
    }

    #[test]
    fn software_pq_key_slot_overflow() {
        let mut pq = SoftwarePostQuantumProvider::new();
        assert_eq!(
            pq.set_key(KeyId(PQ_MAX_KEY_SLOTS as u32), &[1u8; 32]),
            Err(VsError::PolicyViolation)
        );
    }

    #[test]
    fn software_pq_different_keys_different_outputs() {
        let mut pq = SoftwarePostQuantumProvider::new();
        pq.set_key(KeyId(0), &[0x11u8; 32]).unwrap();
        pq.set_key(KeyId(1), &[0x22u8; 32]).unwrap();

        let mut ct0 = [0u8; MLKEM768_CIPHERTEXT_LEN];
        let mut ss0 = [0u8; MLKEM_SHARED_SECRET_LEN];
        pq.mlkem_encapsulate(KeyId(0), &mut ct0, &mut ss0).unwrap();

        let mut ct1 = [0u8; MLKEM768_CIPHERTEXT_LEN];
        let mut ss1 = [0u8; MLKEM_SHARED_SECRET_LEN];
        pq.mlkem_encapsulate(KeyId(1), &mut ct1, &mut ss1).unwrap();

        assert_ne!(
            ss0, ss1,
            "different keys must produce different shared secrets"
        );
    }

    // -----------------------------------------------------------------------
    // NonceCounter tests (8-byte prefix)
    // -----------------------------------------------------------------------

    #[test]
    fn nonce_counter_basic() {
        let mut nc = NonceCounter::new([1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        assert_eq!(nc.count(), 0);
        let n1 = nc.next().unwrap();
        assert_eq!(&n1[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&n1[8..], &1u32.to_be_bytes());
        assert_eq!(nc.count(), 1);
    }

    #[test]
    fn nonce_counter_monotonic() {
        let mut nc = NonceCounter::new([1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let n1 = nc.next().unwrap();
        let n2 = nc.next().unwrap();
        assert_ne!(n1, n2);
        // Counter portion is in last 4 bytes, must be increasing
        let c1 = u32::from_be_bytes([n1[8], n1[9], n1[10], n1[11]]);
        let c2 = u32::from_be_bytes([n2[8], n2[9], n2[10], n2[11]]);
        assert!(c2 > c1);
    }

    #[test]
    fn nonce_counter_persisted_adds_safety_margin() {
        let nc = NonceCounter::new_persisted([1, 0, 0, 0, 0, 0, 0, 0], 100).unwrap();
        assert_eq!(nc.count(), 100 + 1024);
    }

    #[test]
    fn nonce_counter_persisted_overflow_returns_error() {
        // u32::MAX + default margin (1024) overflows → ResourceExhausted
        let result = NonceCounter::new_persisted([1, 0, 0, 0, 0, 0, 0, 0], u32::MAX);
        assert_eq!(result, Err(VsError::ResourceExhausted));
    }

    #[test]
    fn nonce_counter_persisted_near_max_succeeds() {
        // Value that fits: (u32::MAX - 1024) + 1024 = u32::MAX
        let nc = NonceCounter::new_persisted(
            [1, 0, 0, 0, 0, 0, 0, 0],
            u32::MAX - NonceCounter::DEFAULT_REBOOT_SAFETY_MARGIN,
        )
        .unwrap();
        assert_eq!(nc.count(), u32::MAX);
    }

    #[test]
    fn nonce_counter_new_rejects_zero_prefix() {
        let result = NonceCounter::new([0; 8]);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn nonce_counter_persisted_rejects_zero_prefix() {
        let result = NonceCounter::new_persisted([0; 8], 100);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn nonce_counter_custom_safety_margin() {
        let nc =
            NonceCounter::new_persisted_with_margin([1, 0, 0, 0, 0, 0, 0, 0], 100, 5000).unwrap();
        assert_eq!(nc.count(), 5100);
    }

    #[test]
    fn nonce_counter_exhaustion() {
        let mut nc = NonceCounter::new([1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        nc.counter = u32::MAX;
        assert_eq!(nc.next(), Err(VsError::ResourceExhausted));
    }

    #[test]
    fn nonce_counter_random_prefix() {
        let nc = NonceCounter::new_random_prefix([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE])
            .unwrap();
        assert_eq!(nc.count(), 0);
        assert_eq!(
            &nc.prefix,
            &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]
        );
    }

    #[test]
    fn nonce_counter_random_prefix_zero_rejected() {
        assert_eq!(
            NonceCounter::new_random_prefix([0u8; 8]),
            Err(VsError::InvalidInput),
            "all-zero random prefix must be rejected"
        );
    }

    #[test]
    fn nonce_counter_persistence_value() {
        let mut nc = NonceCounter::new([1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        nc.next().unwrap();
        nc.next().unwrap();
        assert_eq!(nc.counter_for_persistence(), 2);
    }

    // `nonce_counter_last_counter_value_matches_count` was removed in 0.7.0
    // along with the deprecated `last_counter_value` method.
    // `counter_for_persistence` is exercised by
    // `nonce_counter_persistence_value` above.

    #[test]
    fn nonce_counter_persist_restore_no_reuse() {
        // Simulate a session that generates some nonces, persists, then reboots.
        let prefix = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44];
        let mut nc = NonceCounter::new(prefix).unwrap();
        for _ in 0..10 {
            nc.next().unwrap();
        }
        let saved = nc.counter_for_persistence();
        assert_eq!(saved, 10);

        // "Reboot": restore from persisted counter.
        let mut nc2 = NonceCounter::new_persisted(prefix, saved).unwrap();
        // The restored counter must be strictly greater than any nonce
        // generated in the previous session.
        assert!(nc2.count() > saved);

        let first_nonce_after_reboot = nc2.next().unwrap();
        let counter_after = u32::from_be_bytes([
            first_nonce_after_reboot[8],
            first_nonce_after_reboot[9],
            first_nonce_after_reboot[10],
            first_nonce_after_reboot[11],
        ]);
        // Must be well past the old session's last counter (10).
        assert!(counter_after > saved);
    }

    #[test]
    fn nonce_counter_persist_restore_custom_margin_no_reuse() {
        let prefix = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut nc = NonceCounter::new(prefix).unwrap();
        for _ in 0..5 {
            nc.next().unwrap();
        }
        let saved = nc.counter_for_persistence();

        let margin = 500;
        let nc2 = NonceCounter::new_persisted_with_margin(prefix, saved, margin).unwrap();
        assert_eq!(nc2.count(), saved + margin);
    }

    #[test]
    fn nonce_counter_persisted_nonces_never_overlap() {
        // Generate nonces in session 1, persist, restore, generate in session 2,
        // and verify no nonce appears in both sessions.
        let prefix = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        let mut nc1 = NonceCounter::new(prefix).unwrap();
        let mut session1_nonces = [[0u8; 12]; 5];
        for nonce in &mut session1_nonces {
            *nonce = nc1.next().unwrap();
        }
        let saved = nc1.counter_for_persistence();

        let mut nc2 = NonceCounter::new_persisted(prefix, saved).unwrap();
        for _ in 0..5 {
            let n = nc2.next().unwrap();
            for s1 in &session1_nonces {
                assert_ne!(&n, s1, "nonce reuse detected across reboot");
            }
        }
    }

    // -----------------------------------------------------------------------
    // SoftwareCryptoProvider tests
    // -----------------------------------------------------------------------

    #[test]
    fn software_crypto_encrypt_decrypt_roundtrip() {
        let mut crypto = SoftwareCryptoProvider::default();
        crypto.set_key(KeyId(0), &[0x42u8; 16]).unwrap();

        let nonce = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];
        let plaintext = b"hello world";
        let mut ct = [0u8; 11];
        let mut tag = [0u8; 16];
        crypto
            .aes_gcm_encrypt(KeyId(0), &nonce, plaintext, b"", &mut ct, &mut tag)
            .unwrap();

        let mut pt_out = [0u8; 11];
        crypto
            .aes_gcm_decrypt(KeyId(0), &nonce, &ct, b"", &tag, &mut pt_out)
            .unwrap();
        assert_eq!(&pt_out, plaintext);
    }

    #[test]
    fn software_crypto_tampered_tag_rejected() {
        let mut crypto = SoftwareCryptoProvider::default();
        crypto.set_key(KeyId(0), &[0x42u8; 16]).unwrap();

        let nonce = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];
        let mut ct = [0u8; 5];
        let mut tag = [0u8; 16];
        crypto
            .aes_gcm_encrypt(KeyId(0), &nonce, b"hello", b"", &mut ct, &mut tag)
            .unwrap();

        tag[0] ^= 0xFF; // tamper
        let mut pt = [0u8; 5];
        assert_eq!(
            crypto.aes_gcm_decrypt(KeyId(0), &nonce, &ct, b"", &tag, &mut pt),
            Err(VsError::CryptoError)
        );
    }

    #[test]
    fn software_crypto_invalid_key_slot() {
        let mut crypto = SoftwareCryptoProvider::default();
        assert_eq!(
            crypto.set_key(KeyId(MOCK_MAX_KEY_SLOTS as u32), &[1u8; 16]),
            Err(VsError::PolicyViolation)
        );
    }

    #[test]
    fn software_crypto_unprovisioned_key() {
        let crypto = SoftwareCryptoProvider::default();
        let mut hash = [0u8; 32];
        assert_eq!(
            crypto.hmac_sha256(KeyId(0), b"data", &mut hash),
            Err(VsError::NotInitialized)
        );
    }

    #[test]
    fn software_crypto_sign_verify_roundtrip() {
        let mut crypto = SoftwareCryptoProvider::default();
        let key_bytes = [0x33u8; 32];
        crypto.set_key(KeyId(0), &key_bytes).unwrap();

        let digest = [0xAAu8; 32];
        let mut sig = [0u8; 64];
        crypto.sign_p256(KeyId(0), &digest, &mut sig).unwrap();

        let mut pub_key = [0u8; 65];
        pub_key[0] = 0x04;
        pub_key[1..33].copy_from_slice(&key_bytes);
        let valid = crypto.verify_p256(&pub_key, &digest, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn software_crypto_different_keys_different_hashes() {
        let mut crypto = SoftwareCryptoProvider::default();
        crypto.set_key(KeyId(0), &[0x11u8; 16]).unwrap();
        crypto.set_key(KeyId(1), &[0x22u8; 16]).unwrap();

        let mut mac0 = [0u8; 32];
        let mut mac1 = [0u8; 32];
        crypto.hmac_sha256(KeyId(0), b"data", &mut mac0).unwrap();
        crypto.hmac_sha256(KeyId(1), b"data", &mut mac1).unwrap();
        assert_ne!(mac0, mac1);
    }

    // -----------------------------------------------------------------------
    // V8: validate_nonce constant-time tests
    // -----------------------------------------------------------------------

    #[test]
    fn validate_nonce_rejects_all_zero() {
        let crypto = SoftwareCryptoProvider::default();
        let nonce = [0u8; 12];
        assert_eq!(crypto.validate_nonce(&nonce), Err(VsError::InvalidInput));
    }

    #[test]
    fn validate_nonce_rejects_all_same() {
        let crypto = SoftwareCryptoProvider::default();
        let nonce = [0xAA; 12];
        assert_eq!(crypto.validate_nonce(&nonce), Err(VsError::InvalidInput));
    }

    #[test]
    fn validate_nonce_accepts_valid() {
        let crypto = SoftwareCryptoProvider::default();
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        assert!(crypto.validate_nonce(&nonce).is_ok());
    }

    #[test]
    fn validate_nonce_rejects_wrong_length() {
        let crypto = SoftwareCryptoProvider::default();
        assert_eq!(crypto.validate_nonce(&[1; 11]), Err(VsError::InvalidInput));
        assert_eq!(crypto.validate_nonce(&[1; 13]), Err(VsError::InvalidInput));
    }

    // -----------------------------------------------------------------------
    // V8: NonceTracker tests
    // -----------------------------------------------------------------------

    #[test]
    fn nonce_tracker_accepts_unique_nonces() {
        let mut tracker = NonceTracker::new();
        assert!(tracker.is_empty());

        let n1 = [1u8; 12];
        let n2 = [2u8; 12];
        tracker.check_and_record(&n1).unwrap();
        tracker.check_and_record(&n2).unwrap();
        assert_eq!(tracker.len(), 2);
    }

    #[test]
    fn nonce_tracker_rejects_duplicate() {
        let mut tracker = NonceTracker::new();
        let nonce = [0x42u8; 12];
        tracker.check_and_record(&nonce).unwrap();
        assert_eq!(
            tracker.check_and_record(&nonce),
            Err(VsError::PolicyViolation)
        );
    }

    #[test]
    fn nonce_tracker_evicts_after_capacity() {
        let mut tracker = NonceTracker::new();
        // Fill the ring completely with unique nonces (slots 0..63).
        for i in 0..NONCE_TRACKER_CAPACITY {
            let mut nonce = [0u8; 12];
            nonce[0] = i as u8;
            nonce[1] = (i >> 8) as u8;
            tracker.check_and_record(&nonce).unwrap();
        }
        assert_eq!(tracker.len(), NONCE_TRACKER_CAPACITY);

        // Insert one more nonce to trigger eviction of slot 0 (the first
        // nonce). This overwrites ring[0] with the new nonce.
        let mut evict_trigger = [0u8; 12];
        evict_trigger[0] = 0xFF;
        evict_trigger[1] = 0xFF;
        tracker.check_and_record(&evict_trigger).unwrap();

        // The first nonce ([0, 0, ...]) was at ring[0] and has now been
        // overwritten. Re-using it should succeed since it's no longer
        // in the ring.
        let first = [0u8; 12];
        tracker.check_and_record(&first).unwrap();
    }

    #[test]
    fn nonce_tracker_persistence_required_rejects_before_init() {
        let mut tracker = NonceTracker::new_with_persistence_required();
        let nonce = [0xABu8; 12];
        assert_eq!(
            tracker.check_and_record(&nonce),
            Err(VsError::NotInitialized),
            "tracker must reject nonces before mark_initialized is called"
        );
    }

    #[test]
    fn nonce_tracker_persistence_required_accepts_after_init() {
        let mut tracker = NonceTracker::new_with_persistence_required();
        tracker.mark_initialized();
        let nonce = [0xABu8; 12];
        tracker
            .check_and_record(&nonce)
            .expect("tracker must accept nonces after mark_initialized");
    }

    #[test]
    fn nonce_tracker_default_does_not_require_persistence() {
        let mut tracker = NonceTracker::new();
        let nonce = [0xCDu8; 12];
        tracker
            .check_and_record(&nonce)
            .expect("default tracker must not require persistence init");
    }

    /// Helper: count the number of `1` bits in the Bloom filter.
    fn bloom_popcount(t: &NonceTracker) -> u32 {
        t.bloom.iter().map(|w| w.count_ones()).sum()
    }

    #[test]
    fn nonce_tracker_bloom_rebuilds_periodically_on_eviction() {
        // Without rebuild, the Bloom monotonically saturates as we churn
        // through unique nonces. With rebuild, the Bloom popcount is bounded
        // close to the live count (256) rather than approaching all-ones (256
        // bits across 256 buckets).
        let mut tracker = NonceTracker::new();

        // Push enough unique nonces to trigger multiple Bloom rebuilds.
        // BLOOM_REBUILD_INTERVAL = 64; we want at least 3 rebuilds.
        let total = NONCE_TRACKER_CAPACITY + 4 * BLOOM_REBUILD_INTERVAL as usize;
        for i in 0..total {
            let mut nonce = [0u8; 12];
            nonce[0] = (i & 0xFF) as u8;
            nonce[1] = ((i >> 8) & 0xFF) as u8;
            nonce[2] = ((i >> 16) & 0xFF) as u8;
            tracker.check_and_record(&nonce).unwrap();
        }

        // After many evictions plus rebuilds the Bloom should not be fully
        // saturated. Without a rebuild we would expect popcount → 256.
        let popcount = bloom_popcount(&tracker);
        assert!(
            popcount < 256,
            "Bloom filter must not be fully saturated after rebuilds; got popcount={popcount}"
        );
    }

    #[test]
    fn nonce_tracker_rebuild_keeps_live_nonces_detectable() {
        // After a rebuild, all live ring contents must still hash to set bits
        // in the Bloom, so a repeat insert of any live nonce still detects
        // reuse via the constant-time scan path.
        let mut tracker = NonceTracker::new();
        // Fill exactly to capacity. Fill nonces have only `nonce[0]` set, so
        // any sentinel that sets a byte beyond `nonce[0]` to a non-zero value
        // is guaranteed not to collide with a fill nonce.
        for i in 0..NONCE_TRACKER_CAPACITY {
            let mut nonce = [0u8; 12];
            nonce[0] = i as u8;
            tracker.check_and_record(&nonce).unwrap();
        }
        // Force enough evictions to trigger at least one rebuild. Use a
        // fixed marker byte at index 11 so these sentinels cannot collide
        // with any fill nonce above (which has zeros at indices 1..12).
        // Without this marker, the j=0 sentinel `[0xAA, 0, 0, ..., 0]`
        // would collide with the i=0xAA fill nonce and be (correctly)
        // rejected as a replay before any rebuild ever happens.
        for j in 0..BLOOM_REBUILD_INTERVAL as usize {
            let mut nonce = [0u8; 12];
            nonce[0] = 0xAA;
            nonce[1] = j as u8;
            nonce[11] = 0xFF;
            tracker.check_and_record(&nonce).unwrap();
        }

        // Pick a known-live nonce and attempt to replay it. The last live
        // sentinel was at j = BLOOM_REBUILD_INTERVAL - 1.
        let mut replay = [0u8; 12];
        replay[0] = 0xAA;
        replay[1] = (BLOOM_REBUILD_INTERVAL as usize - 1) as u8;
        replay[11] = 0xFF;
        assert_eq!(
            tracker.check_and_record(&replay),
            Err(VsError::PolicyViolation),
            "replay of live nonce must still be detected after Bloom rebuild"
        );
    }

    // -----------------------------------------------------------------------
    // V8: self_test canary
    // -----------------------------------------------------------------------

    #[test]
    fn self_test_passes_on_software_provider() {
        let crypto = SoftwareCryptoProvider::default();
        crypto.self_test().unwrap();
    }

    // -----------------------------------------------------------------------
    // New: validate_nonce all-identical rejection
    // -----------------------------------------------------------------------

    #[test]
    fn validate_nonce_rejects_all_0xff() {
        let crypto = SoftwareCryptoProvider::default();
        assert_eq!(
            crypto.validate_nonce(&[0xFF; 12]),
            Err(VsError::InvalidInput)
        );
    }

    #[test]
    fn validate_nonce_rejects_all_0x01() {
        let crypto = SoftwareCryptoProvider::default();
        assert_eq!(
            crypto.validate_nonce(&[0x01; 12]),
            Err(VsError::InvalidInput)
        );
    }

    // -----------------------------------------------------------------------
    // New: delete_key
    // -----------------------------------------------------------------------

    #[test]
    fn delete_key_clears_slot() {
        let mut crypto = SoftwareCryptoProvider::default();
        crypto.set_key(KeyId(0), &[0x42u8; 16]).unwrap();

        let mut mac = [0u8; 32];
        crypto.hmac_sha256(KeyId(0), b"data", &mut mac).unwrap();

        crypto.delete_key(KeyId(0)).unwrap();
        assert_eq!(
            crypto.hmac_sha256(KeyId(0), b"data", &mut mac),
            Err(VsError::NotInitialized)
        );
    }

    #[test]
    fn delete_key_out_of_range() {
        let mut crypto = SoftwareCryptoProvider::default();
        assert_eq!(
            crypto.delete_key(KeyId(MOCK_MAX_KEY_SLOTS as u32)),
            Err(VsError::PolicyViolation)
        );
    }

    // -----------------------------------------------------------------------
    // New: generate_key
    // -----------------------------------------------------------------------

    #[test]
    fn generate_key_creates_usable_key() {
        let mut crypto = SoftwareCryptoProvider::default();
        crypto.generate_key(KeyId(0), KeyType::Aes256).unwrap();

        // Key should be provisioned and usable for HMAC.
        let mut mac = [0u8; 32];
        crypto.hmac_sha256(KeyId(0), b"data", &mut mac).unwrap();
        // MAC should be non-zero.
        assert_ne!(mac, [0u8; 32]);
    }

    // -----------------------------------------------------------------------
    // New: hmac_verify
    // -----------------------------------------------------------------------

    #[test]
    fn hmac_verify_correct_mac() {
        let mut crypto = SoftwareCryptoProvider::default();
        crypto.set_key(KeyId(0), &[0xBB; 32]).unwrap();

        let mut mac = [0u8; 32];
        crypto.hmac_sha256(KeyId(0), b"msg", &mut mac).unwrap();
        assert!(crypto.hmac_verify(KeyId(0), b"msg", &mac).unwrap());
    }

    #[test]
    fn hmac_verify_wrong_mac() {
        let mut crypto = SoftwareCryptoProvider::default();
        crypto.set_key(KeyId(0), &[0xBB; 32]).unwrap();

        let mac = [0xDE; 32];
        assert!(!crypto.hmac_verify(KeyId(0), b"msg", &mac).unwrap());
    }

    // -----------------------------------------------------------------------
    // New: empty key rejected by mock provider
    // -----------------------------------------------------------------------

    #[test]
    fn mock_provider_rejects_empty_key() {
        let mut crypto = SoftwareCryptoProvider::default();
        assert_eq!(crypto.set_key(KeyId(0), &[]), Err(VsError::InvalidInput));
    }

    // -----------------------------------------------------------------------
    // New: mldsa_sign handles messages > 256 bytes
    // -----------------------------------------------------------------------

    #[test]
    fn software_pq_sign_verify_long_message() {
        let mut pq = SoftwarePostQuantumProvider::new();
        let key_material = [0x55u8; MLDSA65_PUBLIC_KEY_LEN];
        pq.set_key(KeyId(0), &key_material).unwrap();

        let long_msg = [0xAB; 512]; // > 256 bytes
        let mut sig = [0u8; MLDSA65_SIGNATURE_LEN];
        pq.mldsa_sign(KeyId(0), &long_msg, &mut sig).unwrap();

        let valid = pq.mldsa_verify(&key_material, &long_msg, &sig).unwrap();
        assert!(valid, "must verify with long message");

        // Different message of same length must fail.
        let mut other_msg = [0xAB; 512];
        other_msg[300] ^= 0xFF;
        let invalid = pq.mldsa_verify(&key_material, &other_msg, &sig).unwrap();
        assert!(!invalid, "must not verify with different long message");
    }
}
