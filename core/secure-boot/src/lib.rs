// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate alloc;

use zeroize::Zeroize;

// Safety: prevent the insecure SoftwareTpm from compiling in release builds.
#[cfg(all(feature = "software-tpm", not(test), not(debug_assertions)))]
compile_error!(
    "The `software-tpm` feature must not be used in release builds. \
     SoftwareTpm is a software-only TPM emulation that does not provide \
     hardware-backed attestation. Use a real TPM in production."
);

use vs_crypto::{CryptoProvider, KeyId};
use vs_types::VsError;

/// Domain separation tag for chain hash initialization.
/// Prevents cross-protocol attacks where a hash from another context
/// could be mistaken for a valid chain hash.
const CHAIN_HASH_DOMAIN: [u8; 32] = *b"vs-secure-boot-chain-hash-v1\x00\x00\x00\x00";

/// Number of PCR registers.
const PCR_COUNT: usize = 8;

/// Maximum number of public key slots.
const MAX_PUB_KEYS: usize = 16;

/// A stage in the boot chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BootStage {
    Bootloader,
    Hypervisor,
    Os,
    Application(u8),
}

impl core::fmt::Display for BootStage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bootloader => write!(f, "Bootloader"),
            Self::Hypervisor => write!(f, "Hypervisor"),
            Self::Os => write!(f, "OS"),
            Self::Application(n) => write!(f, "Application({n})"),
        }
    }
}

impl BootStage {
    fn ordinal(self) -> u16 {
        match self {
            Self::Bootloader => 0,
            Self::Hypervisor => 1,
            Self::Os => 2,
            Self::Application(n) => u16::from(n) + 3,
        }
    }

    /// Maximum application index that fits within [`PCR_COUNT`] registers.
    ///
    /// Application stages occupy PCR indices 3..PCR_COUNT-1, so the
    /// maximum valid `n` is `PCR_COUNT - 4` (i.e., 4 when PCR_COUNT=8).
    const MAX_APP_INDEX: u8 = (PCR_COUNT - 4) as u8;

    /// PCR register index assigned to this boot stage.
    ///
    /// Different stages extend different PCRs so that individual stages
    /// can be attested independently:
    /// - Bootloader     -> PCR 0
    /// - Hypervisor     -> PCR 1
    /// - Os             -> PCR 2
    /// - Application(n) -> PCR 3 + n  (n <= 4 for PCR_COUNT=8)
    ///
    /// Returns [`VsError::InvalidInput`] if `Application(n)` exceeds the
    /// available PCR register count.
    pub fn pcr_index(self) -> Result<usize, VsError> {
        match self {
            Self::Bootloader => Ok(0),
            Self::Hypervisor => Ok(1),
            Self::Os => Ok(2),
            Self::Application(n) if n <= Self::MAX_APP_INDEX => Ok(3 + (n as usize)),
            Self::Application(_) => Err(VsError::InvalidInput),
        }
    }
}

/// A single entry in the boot chain to verify.
#[derive(Debug, Clone, Copy)]
pub struct BootEntry {
    pub stage: BootStage,
    pub image_hash: [u8; 32],
    pub signature: [u8; 64],
    pub signer_key_id: KeyId,
    pub version: u32,
}

/// Result of a successful boot chain verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootAttestation {
    pub pcr_snapshot: [[u8; 32]; 8],
    pub chain_hash: [u8; 32],
    pub timestamp_us: u64,
}

/// Policy for boot verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootFailurePolicy {
    Halt,
    ReportOnly,
    RequestRollback,
}

/// TPM quote result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpmQuote {
    pub pcr_digest: [u8; 32],
    pub signature: [u8; 64],
    /// 32-byte nonce (256-bit, matching modern cryptographic standards).
    pub nonce: [u8; 32],
}

/// Trait for TPM attestation.
pub trait TpmAttestation {
    /// Generate a signed quote over the selected PCRs.
    ///
    /// `pcr_selection` is a bitmask: bit *i* means include PCR *i*.
    fn quote(&self, pcr_selection: u32, nonce: &[u8; 32]) -> Result<TpmQuote, VsError>;

    /// Extend a PCR: `PCR[index] = SHA-256(PCR[index] || measurement)`.
    fn extend_pcr(&mut self, pcr_index: u32, measurement: &[u8; 32]) -> Result<(), VsError>;

    /// Read the current value of a PCR register.
    fn read_pcr(&self, pcr_index: u32) -> Result<[u8; 32], VsError>;
}

// ---------------------------------------------------------------------------
// SoftwareTpm
// ---------------------------------------------------------------------------

/// Software TPM backed by a [`CryptoProvider`] for proper hashing.
///
/// Uses SHA-256 for PCR extension and digest computation, and a keyed
/// hash construction for quote signing. Suitable for integration testing
/// and development — **not for production attestation**.
#[cfg(any(feature = "software-tpm", test))]
pub struct SoftwareTpm<C: CryptoProvider> {
    pcrs: [[u8; 32]; PCR_COUNT],
    attestation_key: [u8; 32],
    crypto: C,
}

#[cfg(any(feature = "software-tpm", test))]
impl<C: CryptoProvider> SoftwareTpm<C> {
    /// Create a new software TPM with a zero attestation key.
    ///
    /// Use [`Self::new_with_key`] when the quote signature must be
    /// meaningful (e.g. when verifying quotes against a known key).
    pub fn new(crypto: C) -> Self {
        Self {
            pcrs: [[0u8; 32]; PCR_COUNT],
            attestation_key: [0u8; 32],
            crypto,
        }
    }

    /// Create with a custom attestation key.
    pub fn new_with_key(crypto: C, attestation_key: [u8; 32]) -> Self {
        Self {
            pcrs: [[0u8; 32]; PCR_COUNT],
            attestation_key,
            crypto,
        }
    }

    /// Read a PCR register by index. Returns `None` if out of range.
    pub fn pcr(&self, index: usize) -> Option<&[u8; 32]> {
        self.pcrs.get(index)
    }

    /// Compute a SHA-256 digest over the concatenation of selected PCRs.
    fn compute_pcr_digest(&self, selection: u32) -> Result<[u8; 32], VsError> {
        let mut concat_buf = [0u8; PCR_COUNT * 32];
        let mut len = 0usize;
        for i in 0..PCR_COUNT {
            if selection & (1 << i) != 0 {
                concat_buf[len..len + 32].copy_from_slice(&self.pcrs[i]);
                len += 32;
            }
        }
        let mut digest = [0u8; 32];
        self.crypto.sha256(&concat_buf[..len], &mut digest)?;
        zeroize_buf(&mut concat_buf);
        Ok(digest)
    }

    /// Produce a keyed hash signature over the PCR digest and nonce.
    ///
    /// Uses an HMAC-like construction:
    ///   sig[0..32]  = SHA-256(key || pcr_digest || nonce)
    ///   sig[32..64] = SHA-256((key ^ 0x5C) || pcr_digest || nonce)
    fn sign(&self, pcr_digest: &[u8; 32], nonce: &[u8; 32]) -> Result<[u8; 64], VsError> {
        let mut sig = [0u8; 64];
        // Build the message: pcr_digest || nonce
        let mut message = [0u8; 64];
        message[..32].copy_from_slice(pcr_digest);
        message[32..].copy_from_slice(nonce);

        // Standard HMAC-SHA-256: H((K ^ opad) || H((K ^ ipad) || message))
        const BLOCK_SIZE: usize = 64;
        let mut ipad = [0x36u8; BLOCK_SIZE];
        let mut opad = [0x5Cu8; BLOCK_SIZE];
        for i in 0..32 {
            ipad[i] ^= self.attestation_key[i];
            opad[i] ^= self.attestation_key[i];
        }

        // Inner hash: SHA-256(ipad || message)
        let mut inner_input = [0u8; BLOCK_SIZE + 64]; // 64-byte block + 64-byte message
        inner_input[..BLOCK_SIZE].copy_from_slice(&ipad);
        inner_input[BLOCK_SIZE..].copy_from_slice(&message);
        let mut inner_hash = [0u8; 32];
        self.crypto.sha256(&inner_input, &mut inner_hash)?;

        // Outer hash: SHA-256(opad || inner_hash)
        let mut outer_input = [0u8; BLOCK_SIZE + 32]; // 64-byte block + 32-byte hash
        outer_input[..BLOCK_SIZE].copy_from_slice(&opad);
        outer_input[BLOCK_SIZE..].copy_from_slice(&inner_hash);
        let mut outer_hash = [0u8; 32];
        self.crypto.sha256(&outer_input, &mut outer_hash)?;
        sig[..32].copy_from_slice(&outer_hash);

        // Second half: HMAC with different domain separation
        // Use SHA-256(opad' || inner_hash) where opad' uses 0xA5
        let mut opad2 = [0xA5u8; BLOCK_SIZE];
        for i in 0..32 {
            opad2[i] ^= self.attestation_key[i];
        }
        let mut outer_input2 = [0u8; BLOCK_SIZE + 32];
        outer_input2[..BLOCK_SIZE].copy_from_slice(&opad2);
        outer_input2[BLOCK_SIZE..].copy_from_slice(&inner_hash);
        let mut outer_hash2 = [0u8; 32];
        self.crypto.sha256(&outer_input2, &mut outer_hash2)?;
        sig[32..].copy_from_slice(&outer_hash2);

        // Zeroize intermediates
        ipad.zeroize();
        opad.zeroize();
        opad2.zeroize();
        inner_input.zeroize();
        outer_input.zeroize();
        outer_input2.zeroize();
        inner_hash.zeroize();
        outer_hash.zeroize();
        outer_hash2.zeroize();
        message.zeroize();

        Ok(sig)
    }
}

#[cfg(any(feature = "software-tpm", test))]
impl<C: CryptoProvider> Drop for SoftwareTpm<C> {
    fn drop(&mut self) {
        zeroize_buf(&mut self.attestation_key);
        for pcr in &mut self.pcrs {
            zeroize_buf(pcr);
        }
    }
}

#[cfg(any(feature = "software-tpm", test))]
impl<C: CryptoProvider> TpmAttestation for SoftwareTpm<C> {
    fn quote(&self, pcr_selection: u32, nonce: &[u8; 32]) -> Result<TpmQuote, VsError> {
        let pcr_digest = self.compute_pcr_digest(pcr_selection)?;
        let signature = self.sign(&pcr_digest, nonce)?;
        Ok(TpmQuote {
            pcr_digest,
            signature,
            nonce: *nonce,
        })
    }

    fn extend_pcr(&mut self, pcr_index: u32, measurement: &[u8; 32]) -> Result<(), VsError> {
        let idx = pcr_index as usize;
        if idx >= PCR_COUNT {
            return Err(VsError::ResourceExhausted);
        }
        let mut concat = [0u8; 64];
        concat[..32].copy_from_slice(&self.pcrs[idx]);
        concat[32..].copy_from_slice(measurement);
        self.crypto.sha256(&concat, &mut self.pcrs[idx])?;
        zeroize_buf(&mut concat);
        Ok(())
    }

    fn read_pcr(&self, pcr_index: u32) -> Result<[u8; 32], VsError> {
        let idx = pcr_index as usize;
        if idx >= PCR_COUNT {
            return Err(VsError::ResourceExhausted);
        }
        Ok(self.pcrs[idx])
    }
}

// ---------------------------------------------------------------------------
// HardwareTpm
// ---------------------------------------------------------------------------

/// Hardware TPM implementation backed by a [`CryptoProvider`] and an
/// attestation key slot.
///
/// Uses the provider's HMAC-SHA-256 for quote signing and SHA-256 for
/// PCR extension — matching the behaviour of a real hardware TPM. In
/// production, the `CryptoProvider` would delegate to a secure element;
/// for testing, use a software-backed crypto provider implementation.
pub struct HardwareTpm<C: CryptoProvider> {
    pcrs: [[u8; 32]; PCR_COUNT],
    attestation_key_id: KeyId,
    crypto: C,
}

impl<C: CryptoProvider> HardwareTpm<C> {
    pub fn new(crypto: C, attestation_key_id: KeyId) -> Self {
        Self {
            pcrs: [[0u8; 32]; PCR_COUNT],
            attestation_key_id,
            crypto,
        }
    }

    /// Read a PCR register by index. Returns `None` if out of range.
    pub fn pcr(&self, index: usize) -> Option<&[u8; 32]> {
        self.pcrs.get(index)
    }
}

impl<C: CryptoProvider> Drop for HardwareTpm<C> {
    fn drop(&mut self) {
        for pcr in &mut self.pcrs {
            zeroize_buf(pcr);
        }
    }
}

impl<C: CryptoProvider> TpmAttestation for HardwareTpm<C> {
    fn quote(&self, pcr_selection: u32, nonce: &[u8; 32]) -> Result<TpmQuote, VsError> {
        // Compute PCR digest: SHA-256(selected PCRs concatenated)
        let mut concat_buf = [0u8; PCR_COUNT * 32];
        let mut len = 0usize;
        for i in 0..PCR_COUNT {
            if pcr_selection & (1 << i) != 0 {
                concat_buf[len..len + 32].copy_from_slice(&self.pcrs[i]);
                len += 32;
            }
        }
        let mut pcr_digest = [0u8; 32];
        self.crypto.sha256(&concat_buf[..len], &mut pcr_digest)?;

        // Sign with HMAC-SHA-256(attestation_key, pcr_digest || nonce)
        let mut sign_data = [0u8; 64]; // 32 digest + 32 nonce
        sign_data[..32].copy_from_slice(&pcr_digest);
        sign_data[32..].copy_from_slice(nonce);
        let mut hmac = [0u8; 32];
        self.crypto
            .hmac_sha256(self.attestation_key_id, &sign_data, &mut hmac)?;

        // Build 64-byte signature: HMAC || HMAC(HMAC || nonce)
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&hmac);
        let mut second_data = [0u8; 64];
        second_data[..32].copy_from_slice(&hmac);
        second_data[32..].copy_from_slice(nonce);
        let mut hmac2 = [0u8; 32];
        self.crypto
            .hmac_sha256(self.attestation_key_id, &second_data, &mut hmac2)?;
        sig[32..].copy_from_slice(&hmac2);

        zeroize_buf(&mut concat_buf);
        zeroize_buf(&mut sign_data);
        zeroize_buf(&mut hmac);
        zeroize_buf(&mut second_data);
        zeroize_buf(&mut hmac2);

        Ok(TpmQuote {
            pcr_digest,
            signature: sig,
            nonce: *nonce,
        })
    }

    fn extend_pcr(&mut self, pcr_index: u32, measurement: &[u8; 32]) -> Result<(), VsError> {
        let idx = pcr_index as usize;
        if idx >= PCR_COUNT {
            return Err(VsError::ResourceExhausted);
        }
        let mut concat = [0u8; 64];
        concat[..32].copy_from_slice(&self.pcrs[idx]);
        concat[32..].copy_from_slice(measurement);
        self.crypto.sha256(&concat, &mut self.pcrs[idx])?;
        zeroize_buf(&mut concat);
        Ok(())
    }

    fn read_pcr(&self, pcr_index: u32) -> Result<[u8; 32], VsError> {
        let idx = pcr_index as usize;
        if idx >= PCR_COUNT {
            return Err(VsError::ResourceExhausted);
        }
        Ok(self.pcrs[idx])
    }
}

// ---------------------------------------------------------------------------
// Standalone helpers
// ---------------------------------------------------------------------------

/// Extend a PCR value: `PCR_new = SHA-256(PCR_old || measurement)`.
pub fn extend_pcr(
    pcr: &mut [u8; 32],
    measurement: &[u8; 32],
    crypto: &impl CryptoProvider,
) -> Result<(), VsError> {
    let mut concat = [0u8; 64];
    concat[..32].copy_from_slice(pcr);
    concat[32..].copy_from_slice(measurement);
    crypto.sha256(&concat, pcr)?;
    zeroize_buf(&mut concat);
    Ok(())
}

/// Zero a byte buffer using volatile writes that the compiler cannot elide.
///
/// Delegates to the `zeroize` crate which uses `write_volatile` to ensure
/// the clearing is never optimised away, even when the buffer appears dead.
#[inline]
fn zeroize_buf(buf: &mut [u8]) {
    buf.zeroize();
}

// ---------------------------------------------------------------------------
// BootVerifier
// ---------------------------------------------------------------------------

/// Outcome of boot chain verification with policy enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum BootVerificationOutcome {
    /// Boot chain verified successfully.
    Verified(BootAttestation),
    /// Verification failed; policy says halt (do not boot).
    Halt(VsError),
    /// Verification failed; policy says report and continue booting.
    ReportAndContinue(VsError),
    /// Verification failed; policy says request firmware rollback.
    RequestRollback(VsError),
}

/// Boot chain verifier.
///
/// Verifies a sequence of signed boot stage entries, extends PCR
/// registers per-stage, and computes a domain-separated chain hash.
/// Includes anti-replay protection via monotonic timestamp tracking.
pub struct BootVerifier<C: CryptoProvider> {
    crypto: C,
    pub_keys: [[u8; 65]; MAX_PUB_KEYS],
    /// Bitmask tracking which key slots have been populated via
    /// [`Self::register_pub_key`]. Bit *i* is set iff slot *i* contains
    /// a registered key.
    registered_keys: u16,
    failure_policy: BootFailurePolicy,
    /// Timestamp of the most recent successful verification.
    /// Used for anti-replay: subsequent verifications must provide a
    /// strictly greater timestamp.
    last_verified_timestamp: Option<u64>,
    /// Per-stage minimum required version for rollback protection.
    stage_versions: [u32; PCR_COUNT],
}

impl<C: CryptoProvider> BootVerifier<C> {
    pub fn new(crypto: C, failure_policy: BootFailurePolicy) -> Self {
        Self {
            crypto,
            pub_keys: [[0u8; 65]; MAX_PUB_KEYS],
            registered_keys: 0,
            failure_policy,
            last_verified_timestamp: None,
            stage_versions: [0; PCR_COUNT],
        }
    }

    /// Get the configured failure policy.
    pub fn failure_policy(&self) -> BootFailurePolicy {
        self.failure_policy
    }

    /// Set the minimum required version for a boot stage.
    pub fn set_stage_version(&mut self, stage: BootStage, version: u32) -> Result<(), VsError> {
        let idx = stage.pcr_index()?;
        self.stage_versions[idx] = version;
        Ok(())
    }

    /// Get the current minimum version for a boot stage.
    pub fn stage_version(&self, stage: BootStage) -> Result<u32, VsError> {
        Ok(self.stage_versions[stage.pcr_index()?])
    }

    /// Returns `true` if a key has been registered at the given slot.
    pub fn is_key_registered(&self, key_id: KeyId) -> bool {
        let idx = key_id.0 as usize;
        idx < MAX_PUB_KEYS && (self.registered_keys & (1 << idx)) != 0
    }

    /// Register a public key for signature verification.
    ///
    /// The `key_id` is used as the slot index (0..15).
    ///
    /// Returns [`VsError::PolicyViolation`] if the slot already contains a
    /// registered key.  Use `replace_pub_key_authorized` for intentional key
    /// replacement, or `replace_pub_key_unchecked` in test builds only.
    pub fn register_pub_key(&mut self, key_id: KeyId, pub_key: &[u8; 65]) -> Result<(), VsError> {
        let idx = key_id.0 as usize;
        if idx >= self.pub_keys.len() {
            return Err(VsError::ResourceExhausted);
        }
        if self.registered_keys & (1 << idx) != 0 {
            return Err(VsError::PolicyViolation);
        }
        self.pub_keys[idx] = *pub_key;
        self.registered_keys |= 1 << idx;
        Ok(())
    }

    /// Replace a public key slot **without** authorization.
    ///
    /// # Security Warning
    /// This method performs no authorization check and exists only for
    /// test / factory-provisioning scenarios.  Production code paths
    /// reachable from untrusted input must **never** call this method.
    /// Use [`replace_pub_key_authorized`](Self::replace_pub_key_authorized)
    /// instead.
    #[cfg(test)]
    pub(crate) fn replace_pub_key_unchecked(
        &mut self,
        key_id: KeyId,
        pub_key: &[u8; 65],
    ) -> Result<(), VsError> {
        let idx = key_id.0 as usize;
        if idx >= self.pub_keys.len() {
            return Err(VsError::ResourceExhausted);
        }
        self.pub_keys[idx] = *pub_key;
        self.registered_keys |= 1 << idx;
        Ok(())
    }

    /// Replace a public key with authorization.
    ///
    /// Requires a valid signature from an existing registered key over the
    /// new key bytes, proving the caller has authority to perform key rotation.
    pub fn replace_pub_key_authorized(
        &mut self,
        slot: usize,
        new_key: &[u8; 65],
        authorizing_key_id: KeyId,
        authorization_sig: &[u8; 64],
    ) -> Result<(), VsError> {
        if slot >= MAX_PUB_KEYS {
            return Err(VsError::ResourceExhausted);
        }
        // Verify that the authorizing key is registered
        let auth_idx = authorizing_key_id.get() as usize;
        if auth_idx >= MAX_PUB_KEYS || (self.registered_keys & (1 << auth_idx)) == 0 {
            return Err(VsError::AuthenticationFailure);
        }
        // Include slot index in digest to prevent cross-slot replay
        let mut digest_input = [0u8; 4 + 65]; // slot(4) + key(65)
        digest_input[..4].copy_from_slice(&(slot as u32).to_be_bytes());
        digest_input[4..].copy_from_slice(new_key);
        let mut digest = [0u8; 32];
        self.crypto.sha256(&digest_input, &mut digest)?;
        // Verify authorization signature
        let auth_key = &self.pub_keys[auth_idx];
        let verified = self
            .crypto
            .verify_p256(auth_key, &digest, authorization_sig)?;
        if !verified {
            return Err(VsError::AuthenticationFailure);
        }
        // Authorized - perform the replacement
        self.pub_keys[slot] = *new_key;
        self.registered_keys |= 1 << slot;
        Ok(())
    }

    /// Verify a boot chain. Returns attestation on success.
    ///
    /// Each boot stage extends a stage-specific PCR register and the
    /// chain hash is domain-separated. The `timestamp_us` must be
    /// strictly greater than the previous successful verification's
    /// timestamp to prevent replay.
    pub fn verify_boot_chain(
        &mut self,
        entries: &[BootEntry],
        timestamp_us: u64,
    ) -> Result<BootAttestation, VsError> {
        if entries.is_empty() {
            return Err(VsError::IntegrityFailure);
        }

        // Anti-replay: timestamp must strictly advance after first use.
        if let Some(last_ts) = self.last_verified_timestamp {
            if timestamp_us <= last_ts {
                return Err(VsError::PolicyViolation);
            }
        }

        // Verify stages are strictly ordered.
        for i in 1..entries.len() {
            if entries[i].stage.ordinal() <= entries[i - 1].stage.ordinal() {
                return Err(VsError::IntegrityFailure);
            }
        }

        let mut pcrs = [[0u8; 32]; PCR_COUNT];

        // Initialize chain hash with domain separation tag.
        let mut chain_hash = [0u8; 32];
        self.crypto.sha256(&CHAIN_HASH_DOMAIN, &mut chain_hash)?;

        for entry in entries {
            // Verify the key slot is registered.
            let key_idx = entry.signer_key_id.0 as usize;
            if key_idx >= self.pub_keys.len() || (self.registered_keys & (1 << key_idx)) == 0 {
                return Err(VsError::AuthenticationFailure);
            }

            let valid = self.crypto.verify_p256(
                &self.pub_keys[key_idx],
                &entry.image_hash,
                &entry.signature,
            )?;

            if !valid {
                return Err(VsError::AuthenticationFailure);
            }

            // Rollback protection: verify version meets minimum
            let pcr_idx = entry.stage.pcr_index()?;
            if entry.version < self.stage_versions[pcr_idx] {
                return Err(VsError::IntegrityFailure);
            }

            // For Application(n), bind the app ID into the measurement
            let measurement = match entry.stage {
                BootStage::Application(n) => {
                    let mut app_data = [0u8; 33]; // 1 byte app_id + 32 bytes hash
                    app_data[0] = n;
                    app_data[1..33].copy_from_slice(&entry.image_hash);
                    let mut app_measurement = [0u8; 32];
                    self.crypto.sha256(&app_data, &mut app_measurement)?;
                    // Zeroize intermediate buffer containing hash material.
                    zeroize_buf(&mut app_data);
                    app_measurement
                }
                _ => entry.image_hash,
            };

            // Extend the stage-appropriate PCR.
            let pcr_idx = entry.stage.pcr_index()?;
            extend_pcr(&mut pcrs[pcr_idx], &measurement, &self.crypto)?;

            // Accumulate chain hash.
            let mut concat = [0u8; 64];
            concat[..32].copy_from_slice(&chain_hash);
            concat[32..].copy_from_slice(&entry.image_hash);
            self.crypto.sha256(&concat, &mut chain_hash)?;
            zeroize_buf(&mut concat);
        }

        // Update minimum versions after successful verification
        for entry in entries {
            let pcr_idx = entry.stage.pcr_index()?;
            if entry.version > self.stage_versions[pcr_idx] {
                self.stage_versions[pcr_idx] = entry.version;
            }
        }

        self.last_verified_timestamp = Some(timestamp_us);

        Ok(BootAttestation {
            pcr_snapshot: pcrs,
            chain_hash,
            timestamp_us,
        })
    }

    /// Verify the boot chain and apply the configured [`BootFailurePolicy`].
    ///
    /// On success, returns [`BootVerificationOutcome::Verified`].
    /// On failure, the outcome depends on the policy:
    /// - [`BootFailurePolicy::Halt`] -> [`BootVerificationOutcome::Halt`]
    /// - [`BootFailurePolicy::ReportOnly`] -> [`BootVerificationOutcome::ReportAndContinue`]
    /// - [`BootFailurePolicy::RequestRollback`] -> [`BootVerificationOutcome::RequestRollback`]
    pub fn verify_boot_chain_with_policy(
        &mut self,
        entries: &[BootEntry],
        timestamp_us: u64,
    ) -> BootVerificationOutcome {
        match self.verify_boot_chain(entries, timestamp_us) {
            Ok(att) => BootVerificationOutcome::Verified(att),
            Err(e) => match self.failure_policy {
                BootFailurePolicy::Halt => BootVerificationOutcome::Halt(e),
                BootFailurePolicy::ReportOnly => BootVerificationOutcome::ReportAndContinue(e),
                BootFailurePolicy::RequestRollback => BootVerificationOutcome::RequestRollback(e),
            },
        }
    }
}

impl<C: CryptoProvider> Drop for BootVerifier<C> {
    fn drop(&mut self) {
        for key in &mut self.pub_keys {
            zeroize_buf(key);
        }
        self.registered_keys = 0;
        self.last_verified_timestamp = None;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use vs_crypto::SoftwareCryptoProvider;

    /// Key material shared between the signing slot and the public key
    /// used for verification. `SoftwareCryptoProvider::verify_p256` uses
    /// `pub_key[1..33]` as the key material, so we mirror it here.
    const TEST_KEY: [u8; 32] = [0x42; 32];

    fn test_crypto() -> SoftwareCryptoProvider {
        let mut c = SoftwareCryptoProvider::default();
        c.set_key(KeyId(0), &TEST_KEY).unwrap();
        c
    }

    /// Build a 65-byte uncompressed public key whose `[1..33]` matches
    /// the key material provisioned in slot 0 of the test crypto.
    fn test_pub_key() -> [u8; 65] {
        let mut pk = [0u8; 65];
        pk[0] = 0x04;
        pk[1..33].copy_from_slice(&TEST_KEY);
        pk
    }

    fn sign_image(crypto: &SoftwareCryptoProvider, image_hash: &[u8; 32]) -> [u8; 64] {
        let mut sig = [0u8; 64];
        crypto.sign_p256(KeyId(0), image_hash, &mut sig).unwrap();
        sig
    }

    // ---- Boot chain verification ----

    #[test]
    fn valid_boot_chain() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let s1 = sign_image(&crypto, &h1);
        let s2 = sign_image(&crypto, &h2);

        let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);
        verifier.register_pub_key(KeyId(0), &pk).unwrap();

        let entries = [
            BootEntry {
                stage: BootStage::Bootloader,
                image_hash: h1,
                signature: s1,
                signer_key_id: KeyId(0),
                version: 1,
            },
            BootEntry {
                stage: BootStage::Os,
                image_hash: h2,
                signature: s2,
                signer_key_id: KeyId(0),
                version: 1,
            },
        ];
        let att = verifier.verify_boot_chain(&entries, 12345).unwrap();
        assert_eq!(att.timestamp_us, 12345);
        assert_ne!(att.pcr_snapshot[0], [0u8; 32]); // Bootloader PCR extended
        assert_ne!(att.pcr_snapshot[2], [0u8; 32]); // Os PCR extended
        assert_eq!(att.pcr_snapshot[1], [0u8; 32]); // Hypervisor PCR untouched
    }

    #[test]
    fn tampered_signature_fails() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);
        verifier.register_pub_key(KeyId(0), &pk).unwrap();

        let entries = [BootEntry {
            stage: BootStage::Bootloader,
            image_hash: [1u8; 32],
            signature: [0xBB; 64],
            signer_key_id: KeyId(0),
            version: 1,
        }];
        assert_eq!(
            verifier.verify_boot_chain(&entries, 1),
            Err(VsError::AuthenticationFailure),
        );
    }

    #[test]
    fn unregistered_key_slot_rejected() {
        let crypto = test_crypto();
        let h = [1u8; 32];
        let s = sign_image(&crypto, &h);

        // Do NOT register any key.
        let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);

        let entries = [BootEntry {
            stage: BootStage::Bootloader,
            image_hash: h,
            signature: s,
            signer_key_id: KeyId(0),
            version: 1,
        }];
        assert_eq!(
            verifier.verify_boot_chain(&entries, 1),
            Err(VsError::AuthenticationFailure),
        );
    }

    #[test]
    fn out_of_order_stages_fail() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let s1 = sign_image(&crypto, &h1);
        let s2 = sign_image(&crypto, &h2);

        let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);
        verifier.register_pub_key(KeyId(0), &pk).unwrap();

        let entries = [
            BootEntry {
                stage: BootStage::Os,
                image_hash: h1,
                signature: s1,
                signer_key_id: KeyId(0),
                version: 1,
            },
            BootEntry {
                stage: BootStage::Bootloader,
                image_hash: h2,
                signature: s2,
                signer_key_id: KeyId(0),
                version: 1,
            },
        ];
        assert_eq!(
            verifier.verify_boot_chain(&entries, 1),
            Err(VsError::IntegrityFailure),
        );
    }

    #[test]
    fn empty_chain_fails() {
        let crypto = test_crypto();
        let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);
        assert_eq!(
            verifier.verify_boot_chain(&[], 1),
            Err(VsError::IntegrityFailure),
        );
    }

    #[test]
    fn duplicate_stages_fail() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let h = [1u8; 32];
        let s = sign_image(&crypto, &h);

        let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);
        verifier.register_pub_key(KeyId(0), &pk).unwrap();

        let entries = [
            BootEntry {
                stage: BootStage::Bootloader,
                image_hash: h,
                signature: s,
                signer_key_id: KeyId(0),
                version: 1,
            },
            BootEntry {
                stage: BootStage::Bootloader,
                image_hash: h,
                signature: s,
                signer_key_id: KeyId(0),
                version: 1,
            },
        ];
        assert_eq!(
            verifier.verify_boot_chain(&entries, 1),
            Err(VsError::IntegrityFailure),
        );
    }

    #[test]
    fn anti_replay_rejects_old_timestamp() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let h = [1u8; 32];
        let s = sign_image(&crypto, &h);

        let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);
        verifier.register_pub_key(KeyId(0), &pk).unwrap();

        let entries = [BootEntry {
            stage: BootStage::Bootloader,
            image_hash: h,
            signature: s,
            signer_key_id: KeyId(0),
            version: 1,
        }];

        // First verification at timestamp 100 succeeds.
        verifier.verify_boot_chain(&entries, 100).unwrap();

        // Same timestamp is rejected (replay).
        assert_eq!(
            verifier.verify_boot_chain(&entries, 100),
            Err(VsError::PolicyViolation),
        );

        // Older timestamp is also rejected.
        assert_eq!(
            verifier.verify_boot_chain(&entries, 50),
            Err(VsError::PolicyViolation),
        );

        // Newer timestamp succeeds.
        verifier.verify_boot_chain(&entries, 200).unwrap();
    }

    #[test]
    fn different_images_produce_different_chain_hashes() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let h_a = [0x01; 32];
        let h_b = [0x02; 32];
        let s_a = sign_image(&crypto, &h_a);
        let s_b = sign_image(&crypto, &h_b);

        let mut verifier_a = BootVerifier::new(test_crypto(), BootFailurePolicy::Halt);
        verifier_a.register_pub_key(KeyId(0), &pk).unwrap();
        let att_a = verifier_a
            .verify_boot_chain(
                &[BootEntry {
                    stage: BootStage::Bootloader,
                    image_hash: h_a,
                    signature: s_a,
                    signer_key_id: KeyId(0),
                    version: 1,
                }],
                1,
            )
            .unwrap();

        let mut verifier_b = BootVerifier::new(crypto, BootFailurePolicy::Halt);
        verifier_b.register_pub_key(KeyId(0), &pk).unwrap();
        let att_b = verifier_b
            .verify_boot_chain(
                &[BootEntry {
                    stage: BootStage::Bootloader,
                    image_hash: h_b,
                    signature: s_b,
                    signer_key_id: KeyId(0),
                    version: 1,
                }],
                1,
            )
            .unwrap();

        assert_ne!(att_a.chain_hash, att_b.chain_hash);
        assert_ne!(att_a.pcr_snapshot[0], att_b.pcr_snapshot[0]);
    }

    #[test]
    fn chain_hash_uses_domain_separation() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let h = [0xAB; 32];
        let s = sign_image(&crypto, &h);

        let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);
        verifier.register_pub_key(KeyId(0), &pk).unwrap();

        let att = verifier
            .verify_boot_chain(
                &[BootEntry {
                    stage: BootStage::Bootloader,
                    image_hash: h,
                    signature: s,
                    signer_key_id: KeyId(0),
                    version: 1,
                }],
                1,
            )
            .unwrap();

        assert_ne!(att.chain_hash, [0u8; 32]);
    }

    #[test]
    fn stages_extend_correct_pcr_indices() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let h1 = [0x10; 32];
        let h2 = [0x20; 32];
        let h3 = [0x30; 32];
        let h4 = [0x40; 32];
        let s1 = sign_image(&crypto, &h1);
        let s2 = sign_image(&crypto, &h2);
        let s3 = sign_image(&crypto, &h3);
        let s4 = sign_image(&crypto, &h4);

        let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);
        verifier.register_pub_key(KeyId(0), &pk).unwrap();

        let entries = [
            BootEntry {
                stage: BootStage::Bootloader,
                image_hash: h1,
                signature: s1,
                signer_key_id: KeyId(0),
                version: 1,
            },
            BootEntry {
                stage: BootStage::Hypervisor,
                image_hash: h2,
                signature: s2,
                signer_key_id: KeyId(0),
                version: 1,
            },
            BootEntry {
                stage: BootStage::Os,
                image_hash: h3,
                signature: s3,
                signer_key_id: KeyId(0),
                version: 1,
            },
            BootEntry {
                stage: BootStage::Application(0),
                image_hash: h4,
                signature: s4,
                signer_key_id: KeyId(0),
                version: 1,
            },
        ];

        let att = verifier.verify_boot_chain(&entries, 1).unwrap();
        for i in 0..4 {
            assert_ne!(att.pcr_snapshot[i], [0u8; 32], "PCR {i} should be extended");
        }
        for i in 4..8 {
            assert_eq!(
                att.pcr_snapshot[i], [0u8; 32],
                "PCR {i} should be untouched"
            );
        }
    }

    // ---- Key registration ----

    #[test]
    fn register_max_pub_keys_then_17th_fails() {
        let mut verifier = BootVerifier::new(test_crypto(), BootFailurePolicy::Halt);
        for i in 0..16u32 {
            verifier.register_pub_key(KeyId(i), &[0x04; 65]).unwrap();
        }
        assert_eq!(
            verifier.register_pub_key(KeyId(16), &[0x04; 65]),
            Err(VsError::ResourceExhausted),
        );
    }

    #[test]
    fn register_pub_key_max_valid_index() {
        let mut verifier = BootVerifier::new(test_crypto(), BootFailurePolicy::Halt);
        assert!(verifier.register_pub_key(KeyId(15), &[0xBB; 65]).is_ok());
        assert!(verifier.is_key_registered(KeyId(15)));
    }

    #[test]
    fn register_pub_key_rejects_overwrite() {
        let mut verifier = BootVerifier::new(test_crypto(), BootFailurePolicy::Halt);
        verifier.register_pub_key(KeyId(0), &[0xAA; 65]).unwrap();
        assert_eq!(
            verifier.register_pub_key(KeyId(0), &[0xBB; 65]),
            Err(VsError::PolicyViolation)
        );
        assert!(verifier.is_key_registered(KeyId(0)));
    }

    #[test]
    fn replace_pub_key_allows_overwrite() {
        let mut verifier = BootVerifier::new(test_crypto(), BootFailurePolicy::Halt);
        verifier.register_pub_key(KeyId(0), &[0xAA; 65]).unwrap();
        verifier
            .replace_pub_key_unchecked(KeyId(0), &[0xBB; 65])
            .unwrap();
        assert!(verifier.is_key_registered(KeyId(0)));
    }

    #[test]
    fn is_key_registered_reflects_state() {
        let mut verifier = BootVerifier::new(test_crypto(), BootFailurePolicy::Halt);
        assert!(!verifier.is_key_registered(KeyId(0)));
        assert!(!verifier.is_key_registered(KeyId(5)));
        verifier.register_pub_key(KeyId(5), &[0x04; 65]).unwrap();
        assert!(!verifier.is_key_registered(KeyId(0)));
        assert!(verifier.is_key_registered(KeyId(5)));
    }

    #[test]
    fn multiple_key_registration_and_verification() {
        let mut crypto = SoftwareCryptoProvider::default();
        let key_a = [0x42; 32];
        let key_b = [0x99; 32];
        crypto.set_key(KeyId(0), &key_a).unwrap();
        crypto.set_key(KeyId(1), &key_b).unwrap();

        let mut pk_a = [0u8; 65];
        pk_a[0] = 0x04;
        pk_a[1..33].copy_from_slice(&key_a);

        let mut pk_b = [0u8; 65];
        pk_b[0] = 0x04;
        pk_b[1..33].copy_from_slice(&key_b);

        let h1 = [0x10; 32];
        let h2 = [0x20; 32];
        let mut s1 = [0u8; 64];
        crypto.sign_p256(KeyId(0), &h1, &mut s1).unwrap();
        let mut s2 = [0u8; 64];
        crypto.sign_p256(KeyId(1), &h2, &mut s2).unwrap();

        let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);
        verifier.register_pub_key(KeyId(0), &pk_a).unwrap();
        verifier.register_pub_key(KeyId(1), &pk_b).unwrap();

        let entries = [
            BootEntry {
                stage: BootStage::Bootloader,
                image_hash: h1,
                signature: s1,
                signer_key_id: KeyId(0),
                version: 1,
            },
            BootEntry {
                stage: BootStage::Os,
                image_hash: h2,
                signature: s2,
                signer_key_id: KeyId(1),
                version: 1,
            },
        ];
        verifier.verify_boot_chain(&entries, 1).unwrap();
    }

    // ---- PCR extension ----

    #[test]
    fn pcr_extension_deterministic() {
        let crypto = test_crypto();
        let measurement = [0xAB; 32];

        let mut pcr = [0u8; 32];
        extend_pcr(&mut pcr, &measurement, &crypto).unwrap();
        let first = pcr;

        pcr = [0u8; 32];
        extend_pcr(&mut pcr, &measurement, &crypto).unwrap();
        assert_eq!(pcr, first);
    }

    #[test]
    fn pcr_extension_multiple_replay() {
        let crypto = test_crypto();
        let m1 = [0x11; 32];
        let m2 = [0x22; 32];
        let m3 = [0x33; 32];

        let mut pcr = [0u8; 32];
        extend_pcr(&mut pcr, &m1, &crypto).unwrap();
        extend_pcr(&mut pcr, &m2, &crypto).unwrap();
        extend_pcr(&mut pcr, &m3, &crypto).unwrap();

        let mut pcr2 = [0u8; 32];
        extend_pcr(&mut pcr2, &m1, &crypto).unwrap();
        extend_pcr(&mut pcr2, &m2, &crypto).unwrap();
        extend_pcr(&mut pcr2, &m3, &crypto).unwrap();

        assert_eq!(pcr, pcr2);
    }

    #[test]
    fn pcr_extension_order_matters() {
        let crypto = test_crypto();
        let m1 = [0x11; 32];
        let m2 = [0x22; 32];

        let mut pcr_ab = [0u8; 32];
        extend_pcr(&mut pcr_ab, &m1, &crypto).unwrap();
        extend_pcr(&mut pcr_ab, &m2, &crypto).unwrap();

        let mut pcr_ba = [0u8; 32];
        extend_pcr(&mut pcr_ba, &m2, &crypto).unwrap();
        extend_pcr(&mut pcr_ba, &m1, &crypto).unwrap();

        assert_ne!(pcr_ab, pcr_ba);
    }

    #[test]
    fn pcr_extension_with_all_ff_measurement() {
        let crypto = test_crypto();
        let mut pcr = [0u8; 32];
        extend_pcr(&mut pcr, &[0xFF; 32], &crypto).unwrap();
        assert_ne!(pcr, [0u8; 32]);
    }

    // ---- SoftwareTpm ----

    #[test]
    fn software_tpm_quote() {
        let tpm = SoftwareTpm::new(test_crypto());
        let nonce = [0x42u8; 32];
        let quote = tpm.quote(1, &nonce).unwrap();
        assert_eq!(quote.nonce, nonce);
        assert_ne!(quote.signature, [0u8; 64]);
    }

    #[test]
    fn software_tpm_quote_deterministic() {
        let tpm = SoftwareTpm::new(test_crypto());
        let nonce = [0x42u8; 32];
        let q1 = tpm.quote(1, &nonce).unwrap();
        let q2 = tpm.quote(1, &nonce).unwrap();
        assert_eq!(q1.signature, q2.signature);
        assert_eq!(q1.pcr_digest, q2.pcr_digest);
    }

    #[test]
    fn software_tpm_quote_varies_with_nonce() {
        let tpm = SoftwareTpm::new(test_crypto());
        let q1 = tpm.quote(1, &[0x01; 32]).unwrap();
        let q2 = tpm.quote(1, &[0x02; 32]).unwrap();
        assert_ne!(q1.signature, q2.signature);
    }

    #[test]
    fn software_tpm_extend_and_read_pcr() {
        let mut tpm = SoftwareTpm::new(test_crypto());
        let measurement = [0xAB; 32];
        tpm.extend_pcr(0, &measurement).unwrap();
        let pcr = tpm.read_pcr(0).unwrap();
        assert_ne!(pcr, [0u8; 32]);
        // SHA-256 based: result differs from raw measurement
        assert_ne!(pcr, measurement);
    }

    #[test]
    fn software_tpm_extend_is_hash_based_not_xor() {
        // Extending twice with the same value must NOT cancel out.
        // XOR: A ^ A = 0. SHA-256: H(H(0||A)||A) != 0.
        let mut tpm = SoftwareTpm::new(test_crypto());
        let m = [0xAA; 32];
        tpm.extend_pcr(0, &m).unwrap();
        tpm.extend_pcr(0, &m).unwrap();
        let pcr = tpm.read_pcr(0).unwrap();
        assert_ne!(pcr, [0u8; 32], "double extend must not cancel out");
    }

    #[test]
    fn software_tpm_extend_pcr_out_of_range() {
        let mut tpm = SoftwareTpm::new(test_crypto());
        assert_eq!(tpm.extend_pcr(8, &[0; 32]), Err(VsError::ResourceExhausted));
    }

    #[test]
    fn software_tpm_read_pcr_out_of_range() {
        let tpm = SoftwareTpm::new(test_crypto());
        assert_eq!(tpm.read_pcr(8), Err(VsError::ResourceExhausted));
    }

    #[test]
    fn software_tpm_pcr_accessor() {
        let tpm = SoftwareTpm::new(test_crypto());
        assert_eq!(tpm.pcr(0), Some(&[0u8; 32]));
        assert_eq!(tpm.pcr(7), Some(&[0u8; 32]));
        assert_eq!(tpm.pcr(8), None);
    }

    #[test]
    fn software_tpm_quote_pcr_selection() {
        let mut tpm = SoftwareTpm::new(test_crypto());
        tpm.extend_pcr(0, &[0x11; 32]).unwrap();
        tpm.extend_pcr(2, &[0x22; 32]).unwrap();

        let nonce = [0; 32];
        let q1 = tpm.quote(0b001, &nonce).unwrap(); // PCR 0 only
        let q2 = tpm.quote(0b101, &nonce).unwrap(); // PCR 0 + PCR 2
        assert_ne!(q1.pcr_digest, q2.pcr_digest);
    }

    #[test]
    fn software_tpm_new_with_key() {
        let key = [0xFF; 32];
        let tpm = SoftwareTpm::new_with_key(test_crypto(), key);
        let nonce = [0; 32];
        let quote = tpm.quote(1, &nonce).unwrap();
        assert_ne!(quote.signature, [0u8; 64]);
    }

    #[test]
    fn software_tpm_different_keys_produce_different_signatures() {
        let nonce = [0x42; 32];
        let tpm_a = SoftwareTpm::new_with_key(test_crypto(), [0xAA; 32]);
        let tpm_b = SoftwareTpm::new_with_key(test_crypto(), [0xBB; 32]);
        let q_a = tpm_a.quote(0, &nonce).unwrap();
        let q_b = tpm_b.quote(0, &nonce).unwrap();
        assert_ne!(q_a.signature, q_b.signature);
    }

    // ---- HardwareTpm ----

    #[test]
    fn hardware_tpm_quote_works() {
        let mut crypto = SoftwareCryptoProvider::default();
        crypto.set_key(KeyId(0), &[0x42; 32]).unwrap();
        let tpm = HardwareTpm::new(crypto, KeyId(0));

        let nonce = [0x42u8; 32];
        let quote = tpm.quote(1, &nonce).unwrap();
        assert_eq!(quote.nonce, nonce);
        assert_ne!(quote.signature, [0u8; 64]);
    }

    #[test]
    fn hardware_tpm_quote_deterministic() {
        let mut crypto = SoftwareCryptoProvider::default();
        crypto.set_key(KeyId(0), &[0x42; 32]).unwrap();
        let tpm = HardwareTpm::new(crypto, KeyId(0));

        let nonce = [0x42u8; 32];
        let q1 = tpm.quote(1, &nonce).unwrap();
        let q2 = tpm.quote(1, &nonce).unwrap();
        assert_eq!(q1.signature, q2.signature);
    }

    #[test]
    fn hardware_tpm_extend_and_read_pcr() {
        let crypto = SoftwareCryptoProvider::default();
        let mut tpm = HardwareTpm::new(crypto, KeyId(0));
        let measurement = [0xAB; 32];
        tpm.extend_pcr(0, &measurement).unwrap();
        let pcr = tpm.read_pcr(0).unwrap();
        assert_ne!(pcr, [0u8; 32]);
    }

    #[test]
    fn hardware_tpm_extend_pcr_out_of_range() {
        let crypto = SoftwareCryptoProvider::default();
        let mut tpm = HardwareTpm::new(crypto, KeyId(0));
        assert_eq!(tpm.extend_pcr(8, &[0; 32]), Err(VsError::ResourceExhausted));
    }

    #[test]
    fn hardware_tpm_read_pcr_out_of_range() {
        let crypto = SoftwareCryptoProvider::default();
        let tpm = HardwareTpm::new(crypto, KeyId(0));
        assert_eq!(tpm.read_pcr(8), Err(VsError::ResourceExhausted));
    }

    #[test]
    fn hardware_tpm_pcr_accessor() {
        let crypto = SoftwareCryptoProvider::default();
        let tpm = HardwareTpm::new(crypto, KeyId(0));
        assert_eq!(tpm.pcr(0), Some(&[0u8; 32]));
        assert_eq!(tpm.pcr(8), None);
    }

    #[test]
    fn hardware_tpm_unkeyed_slot_fails() {
        // CryptoProvider slot 5 has no key -> hmac_sha256 should fail.
        let crypto = SoftwareCryptoProvider::default();
        let tpm = HardwareTpm::new(crypto, KeyId(5));
        let result = tpm.quote(1, &[0; 32]);
        assert_eq!(result, Err(VsError::NotInitialized));
    }

    // ---- BootVerificationOutcome / policy ----

    #[test]
    fn verify_with_policy_halt_on_failure() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);
        verifier.register_pub_key(KeyId(0), &pk).unwrap();

        let entries = [BootEntry {
            stage: BootStage::Bootloader,
            image_hash: [1u8; 32],
            signature: [0xBB; 64],
            signer_key_id: KeyId(0),
            version: 1,
        }];
        assert_eq!(
            verifier.verify_boot_chain_with_policy(&entries, 1),
            BootVerificationOutcome::Halt(VsError::AuthenticationFailure),
        );
    }

    #[test]
    fn verify_with_policy_report_on_failure() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::ReportOnly);
        verifier.register_pub_key(KeyId(0), &pk).unwrap();

        let entries = [BootEntry {
            stage: BootStage::Bootloader,
            image_hash: [1u8; 32],
            signature: [0xBB; 64],
            signer_key_id: KeyId(0),
            version: 1,
        }];
        assert_eq!(
            verifier.verify_boot_chain_with_policy(&entries, 1),
            BootVerificationOutcome::ReportAndContinue(VsError::AuthenticationFailure),
        );
    }

    #[test]
    fn verify_with_policy_rollback_on_failure() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::RequestRollback);
        verifier.register_pub_key(KeyId(0), &pk).unwrap();

        let entries = [BootEntry {
            stage: BootStage::Bootloader,
            image_hash: [1u8; 32],
            signature: [0xBB; 64],
            signer_key_id: KeyId(0),
            version: 1,
        }];
        assert_eq!(
            verifier.verify_boot_chain_with_policy(&entries, 1),
            BootVerificationOutcome::RequestRollback(VsError::AuthenticationFailure),
        );
    }

    #[test]
    fn verify_with_policy_success() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let h = [1u8; 32];
        let s = sign_image(&crypto, &h);

        let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);
        verifier.register_pub_key(KeyId(0), &pk).unwrap();

        let entries = [BootEntry {
            stage: BootStage::Bootloader,
            image_hash: h,
            signature: s,
            signer_key_id: KeyId(0),
            version: 1,
        }];
        match verifier.verify_boot_chain_with_policy(&entries, 42) {
            BootVerificationOutcome::Verified(att) => assert_eq!(att.timestamp_us, 42),
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[test]
    fn failure_policy_getter() {
        let v = BootVerifier::new(test_crypto(), BootFailurePolicy::ReportOnly);
        assert_eq!(v.failure_policy(), BootFailurePolicy::ReportOnly);
    }

    // ---- BootStage ----

    #[test]
    fn boot_stage_ordinals_are_correct() {
        assert_eq!(BootStage::Bootloader.ordinal(), 0);
        assert_eq!(BootStage::Hypervisor.ordinal(), 1);
        assert_eq!(BootStage::Os.ordinal(), 2);
        assert_eq!(BootStage::Application(0).ordinal(), 3);
        assert_eq!(BootStage::Application(1).ordinal(), 4);
        assert_eq!(BootStage::Application(255).ordinal(), 258);
    }

    #[test]
    fn boot_stage_pcr_indices() {
        assert_eq!(BootStage::Bootloader.pcr_index(), Ok(0));
        assert_eq!(BootStage::Hypervisor.pcr_index(), Ok(1));
        assert_eq!(BootStage::Os.pcr_index(), Ok(2));
        assert_eq!(BootStage::Application(0).pcr_index(), Ok(3));
        assert_eq!(BootStage::Application(1).pcr_index(), Ok(4));
        assert_eq!(BootStage::Application(4).pcr_index(), Ok(7));
        // Application(5+) exceeds PCR_COUNT and must fail.
        assert_eq!(
            BootStage::Application(5).pcr_index(),
            Err(VsError::InvalidInput)
        );
        assert_eq!(
            BootStage::Application(255).pcr_index(),
            Err(VsError::InvalidInput)
        );
    }

    #[test]
    fn set_stage_version_rejects_out_of_range_application() {
        let mut verifier = BootVerifier::new(test_crypto(), BootFailurePolicy::Halt);
        assert_eq!(
            verifier.set_stage_version(BootStage::Application(5), 1),
            Err(VsError::InvalidInput)
        );
        // Valid application index succeeds.
        assert!(verifier
            .set_stage_version(BootStage::Application(4), 1)
            .is_ok());
    }

    #[test]
    fn boot_stage_ordering() {
        assert!(BootStage::Bootloader < BootStage::Hypervisor);
        assert!(BootStage::Hypervisor < BootStage::Os);
        assert!(BootStage::Os < BootStage::Application(0));
        assert!(BootStage::Application(0) < BootStage::Application(1));
    }

    #[test]
    fn boot_failure_policy_equality() {
        assert_ne!(BootFailurePolicy::Halt, BootFailurePolicy::ReportOnly);
        assert_ne!(
            BootFailurePolicy::ReportOnly,
            BootFailurePolicy::RequestRollback,
        );
    }

    // ---- Security fix tests ----

    #[test]
    fn anti_replay_allows_first_boot_at_zero() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let h = [1u8; 32];
        let s = sign_image(&crypto, &h);

        let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);
        verifier.register_pub_key(KeyId(0), &pk).unwrap();

        let entries = [BootEntry {
            stage: BootStage::Bootloader,
            image_hash: h,
            signature: s,
            signer_key_id: KeyId(0),
            version: 1,
        }];
        // First boot at timestamp 0 should succeed
        assert!(verifier.verify_boot_chain(&entries, 0).is_ok());
        // Second boot at timestamp 0 should fail
        assert!(verifier.verify_boot_chain(&entries, 0).is_err());
        // Boot at timestamp 1 should succeed
        assert!(verifier.verify_boot_chain(&entries, 1).is_ok());
    }

    #[test]
    fn replace_pub_key_requires_authorization() {
        let crypto = test_crypto();
        let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);
        let pub_key = test_pub_key();
        verifier.register_pub_key(KeyId(0), &pub_key).unwrap();

        let new_key = [0x04u8; 65];
        let bad_sig = [0u8; 64];
        // Unauthorized replacement should fail
        assert!(verifier
            .replace_pub_key_authorized(0, &new_key, KeyId::new(0), &bad_sig)
            .is_err());
    }

    #[test]
    fn application_stages_produce_different_pcr_values() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let h1 = [0x10; 32];
        let h2 = [0xAA; 32];
        let s1 = sign_image(&crypto, &h1);
        let s2 = sign_image(&crypto, &h2);

        let mut v1 = BootVerifier::new(test_crypto(), BootFailurePolicy::Halt);
        let mut v2 = BootVerifier::new(test_crypto(), BootFailurePolicy::Halt);
        v1.register_pub_key(KeyId(0), &pk).unwrap();
        v2.register_pub_key(KeyId(0), &pk).unwrap();

        let chain1 = [
            BootEntry {
                stage: BootStage::Bootloader,
                image_hash: h1,
                signature: s1,
                signer_key_id: KeyId(0),
                version: 1,
            },
            BootEntry {
                stage: BootStage::Application(0),
                image_hash: h2,
                signature: s2,
                signer_key_id: KeyId(0),
                version: 1,
            },
        ];
        let chain2 = [
            BootEntry {
                stage: BootStage::Bootloader,
                image_hash: h1,
                signature: s1,
                signer_key_id: KeyId(0),
                version: 1,
            },
            BootEntry {
                stage: BootStage::Application(1),
                image_hash: h2,
                signature: s2,
                signer_key_id: KeyId(0),
                version: 1,
            },
        ];

        let att1 = v1.verify_boot_chain(&chain1, 1000).unwrap();
        let att2 = v2.verify_boot_chain(&chain2, 1000).unwrap();
        // PCR 3 should differ because app IDs are mixed in
        assert_ne!(att1.pcr_snapshot[3], att2.pcr_snapshot[3]);
    }

    // -- BootStage Display tests ----------------------------------------------

    #[test]
    fn boot_stage_display() {
        use alloc::format;
        assert_eq!(format!("{}", BootStage::Bootloader), "Bootloader");
        assert_eq!(format!("{}", BootStage::Hypervisor), "Hypervisor");
        assert_eq!(format!("{}", BootStage::Os), "OS");
        assert_eq!(format!("{}", BootStage::Application(0)), "Application(0)");
        assert_eq!(format!("{}", BootStage::Application(5)), "Application(5)");
    }
}
