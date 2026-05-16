// SPDX-License-Identifier: Apache-2.0
//! # vs-secure-boot
//!
//! Secure boot chain verification with PCR measurement for Craton Shield.
//!
//! This crate verifies the integrity of the boot chain from bootloader
//! through hypervisor, OS, and (optional) application stages. Each stage's
//! image hash and signature are validated, and measurements are extended
//! into software PCR registers to produce a [`BootAttestation`] snapshot.
//!
//! See [`BootVerifier::verify_boot_chain`] for the full usage example.
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

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

/// Domain separation tag for key-rotation authorization digests.
///
/// Mixed into the pre-image signed by an authorizing key so a rotation
/// authorization signature cannot be confused with a [`BootEntry`]
/// signature or any other protocol's signed input.
const KEY_ROTATION_AUTH_DOMAIN: &[u8; 25] = b"vs-secure-boot-keyrot-v1\x00";

/// Number of PCR registers.
const PCR_COUNT: usize = 8;

/// Maximum number of public key slots.
const MAX_PUB_KEYS: usize = 16;

/// A stage in the boot chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BootStage {
    /// First-stage immutable bootloader (measured into PCR 0).
    Bootloader,
    /// Hypervisor / VMM stage (measured into PCR 1).
    Hypervisor,
    /// Operating-system / kernel stage (measured into PCR 2).
    Os,
    /// Application-level stage `n` (measured into PCR `3 + n`).
    ///
    /// `n` is bounded by `PCR_COUNT` — see [`BootStage::pcr_index`].
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

/// Wire format version for [`BootEntry`] signature payload.
///
/// Bumped from implicit `v1` (image_hash only) to **v2** when the
/// [`BootStage`] discriminant was incorporated into the signed payload.
/// This is a **BREAKING CHANGE** to the on-wire signed format: signatures
/// produced under v1 will not verify under v2 and vice versa. Production
/// deployments must re-sign all boot images when upgrading.
pub const BOOT_ENTRY_SIGNATURE_VERSION: u8 = 2;

/// Domain separation tag for [`BootEntry`] signing digests.
///
/// Mixed into the pre-image to ensure signatures over a boot entry
/// cannot be confused with signatures generated under any other
/// protocol that signs structurally similar inputs.
const BOOT_ENTRY_SIGN_DOMAIN: &[u8; 24] = b"vs-secure-boot-entry-v2\x00";

/// A single entry in the boot chain to verify.
#[derive(Debug, Clone, Copy)]
pub struct BootEntry {
    /// Boot stage this entry attests to.
    pub stage: BootStage,
    /// SHA-256 digest of the stage's binary image.
    pub image_hash: [u8; 32],
    /// ECDSA-P256 signature over the v2 stage-bound signing digest.
    ///
    /// See [`BootEntry::compute_signing_digest`] for the exact pre-image.
    pub signature: [u8; 64],
    /// Slot index of the public key that produced [`Self::signature`].
    pub signer_key_id: KeyId,
    /// Monotonic version counter for rollback protection.
    pub version: u32,
}

impl BootEntry {
    /// Compute the 32-byte digest fed to ECDSA sign/verify for this entry.
    ///
    /// # Wire encoding (v2 — BREAKING change vs v1)
    ///
    /// The pre-image is the byte concatenation, in this exact order:
    ///
    /// 1. `BOOT_ENTRY_SIGN_DOMAIN`        — 24 bytes, domain separation tag
    /// 2. `stage.ordinal()` as little-endian `u32` — 4 bytes
    /// 3. `image_hash`                    — 32 bytes
    ///
    /// The pre-image (60 bytes total) is hashed with SHA-256 to produce
    /// the 32-byte digest passed to `sign_p256` / `verify_p256`.
    ///
    /// Including the stage in the signed payload is a security fix: it
    /// prevents a cross-stage substitution attack where a signature
    /// produced for stage *N* could be replayed under stage *M* by a
    /// signer with valid key material for stage *N*.
    ///
    /// **Wire compatibility:** v1 (image_hash only) signatures will NOT
    /// verify against v2 digests. Re-sign all boot images on upgrade.
    pub fn compute_signing_digest(
        stage: BootStage,
        image_hash: &[u8; 32],
        crypto: &impl CryptoProvider,
    ) -> Result<[u8; 32], VsError> {
        // Pre-image layout: [domain(24) || stage_ordinal_le_u32(4) || image_hash(32)] = 60 bytes
        let mut pre_image = [0u8; 24 + 4 + 32];
        pre_image[..24].copy_from_slice(BOOT_ENTRY_SIGN_DOMAIN);
        // Stage discriminant: BootStage::ordinal() returns u16 (covers all
        // current variants including Application(255) -> 258); we widen to
        // u32-LE for headroom and a fixed-width deterministic encoding.
        let ordinal_bytes = (stage.ordinal() as u32).to_le_bytes();
        pre_image[24..28].copy_from_slice(&ordinal_bytes);
        pre_image[28..60].copy_from_slice(image_hash);
        let mut digest = [0u8; 32];
        crypto.sha256(&pre_image, &mut digest)?;
        zeroize_buf(&mut pre_image);
        Ok(digest)
    }

    /// Sign a [`BootEntry`]'s payload using the v2 wire format.
    ///
    /// Computes the stage-bound digest via [`Self::compute_signing_digest`]
    /// and signs it with `key_id` via the provided [`CryptoProvider`].
    /// See [`Self::compute_signing_digest`] for the exact wire encoding.
    pub fn sign(
        stage: BootStage,
        image_hash: &[u8; 32],
        key_id: KeyId,
        crypto: &impl CryptoProvider,
    ) -> Result<[u8; 64], VsError> {
        let digest = Self::compute_signing_digest(stage, image_hash, crypto)?;
        let mut sig = [0u8; 64];
        crypto.sign_p256(key_id, &digest, &mut sig)?;
        Ok(sig)
    }

    /// Verify this [`BootEntry`]'s signature using the v2 wire format.
    ///
    /// Recomputes the stage-bound digest and verifies the entry's
    /// signature against `pub_key`. Returns `Ok(true)` for a valid
    /// signature, `Ok(false)` for a cryptographically invalid one, and
    /// `Err` only for operational failures.
    #[must_use = "Ok(false) means the signature is INVALID; ignoring this return value accepts forged signatures"]
    pub fn verify(
        &self,
        pub_key: &[u8; 65],
        crypto: &impl CryptoProvider,
    ) -> Result<bool, VsError> {
        let digest = Self::compute_signing_digest(self.stage, &self.image_hash, crypto)?;
        crypto.verify_p256(pub_key, &digest, &self.signature)
    }
}

/// Result of a successful boot chain verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootAttestation {
    /// Final values of the eight PCR registers after replaying the chain.
    pub pcr_snapshot: [[u8; 32]; 8],
    /// Domain-separated SHA-256 digest folding every entry's image hash.
    pub chain_hash: [u8; 32],
    /// Monotonic timestamp of the verification (microseconds).
    pub timestamp_us: u64,
}

/// Policy for boot verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootFailurePolicy {
    /// Halt the boot on any verification error.
    Halt,
    /// Continue booting but surface the error to the caller for logging.
    ReportOnly,
    /// Request a firmware rollback (e.g. to a known-good slot).
    RequestRollback,
}

/// TPM quote result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpmQuote {
    /// SHA-256 digest over the selected PCR registers.
    pub pcr_digest: [u8; 32],
    /// 64-byte signature over `pcr_digest || nonce`.
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
    ///
    /// Returns [`VsError::InvalidInput`] when `selection == 0`. Hashing an
    /// empty buffer would produce the constant SHA-256 of the empty
    /// string, which is meaningless as an attestation and would let a
    /// caller obtain a "quote" without ever measuring a PCR.
    fn compute_pcr_digest(&self, selection: u32) -> Result<[u8; 32], VsError> {
        if selection == 0 {
            return Err(VsError::InvalidInput);
        }
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
    /// Create a `HardwareTpm` bound to an attestation key slot in the
    /// supplied [`CryptoProvider`].
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
        // Reject empty PCR selection — see `SoftwareTpm::compute_pcr_digest`
        // for rationale. A zero selection would otherwise hash an empty
        // buffer and produce a quote that attests to nothing.
        if pcr_selection == 0 {
            return Err(VsError::InvalidInput);
        }
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

/// Persistable rollback-protection state for a [`BootVerifier`].
///
/// # Why this exists (security-critical)
///
/// Rollback protection and anti-replay are only meaningful if their
/// state **survives a power cycle**. The relevant state is:
///
/// - `last_verified_timestamp` — anti-replay floor; a verification must
///   present a strictly greater timestamp than any previous one.
/// - `stage_versions` — per-PCR minimum accepted image version; an image
///   whose `version` is below the recorded floor is a downgrade and is
///   rejected.
/// - `key_rotation_counter` — monotonic anti-replay counter bound into
///   every [`BootVerifier::replace_pub_key_authorized`] authorization
///   digest, so a captured rotation message cannot be replayed later.
///
/// A freshly constructed [`BootVerifier`] starts with an all-zero floor.
/// If that zero floor is used on every boot, rollback protection and key
/// rotation replay protection reset to nothing each power cycle and
/// protect against nothing.
///
/// **The caller is responsible** for persisting this struct to
/// non-volatile storage (an NV counter, monotonic fuse, or replay-safe
/// flash region) after every successful verification / key rotation, and
/// for re-seeding it via [`BootVerifier::new_persisted`] on the next
/// boot. Treat the floor like an NV monotonic counter: it may only ever
/// move forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollbackFloor {
    /// Timestamp of the most recent successful verification, if any.
    pub last_verified_timestamp: Option<u64>,
    /// Per-PCR-index minimum accepted image version.
    pub stage_versions: [u32; PCR_COUNT],
    /// Monotonic counter consumed by authorized key rotation. Each
    /// successful [`BootVerifier::replace_pub_key_authorized`] requires a
    /// signature bound to the current value and then increments it.
    pub key_rotation_counter: u64,
}

impl RollbackFloor {
    /// An empty floor — equivalent to a device that has never recorded a
    /// boot. Using this on a production boot disables rollback / replay
    /// protection; prefer restoring a persisted floor via
    /// [`BootVerifier::new_persisted`].
    pub const EMPTY: Self = Self {
        last_verified_timestamp: None,
        stage_versions: [0; PCR_COUNT],
        key_rotation_counter: 0,
    };
}

impl Default for RollbackFloor {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Boot chain verifier.
///
/// Verifies a sequence of signed boot stage entries, extends PCR
/// registers per-stage, and computes a domain-separated chain hash.
/// Includes anti-replay protection via monotonic timestamp tracking.
///
/// # Persistence requirement
///
/// The rollback / anti-replay state ([`RollbackFloor`]) lives only in
/// this struct and is **not** automatically persisted. For rollback
/// protection to survive a power cycle the caller MUST persist
/// [`Self::floor_for_persistence`] to non-volatile storage and restore it
/// on the next boot via [`Self::new_persisted`]. A verifier built with
/// [`Self::new`] starts from an empty floor and provides no cross-reboot
/// rollback protection.
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
    /// Monotonic anti-replay counter for authorized key rotation.
    /// Bound into every key-rotation authorization digest and
    /// incremented after each successful rotation.
    key_rotation_counter: u64,
}

impl<C: CryptoProvider> BootVerifier<C> {
    /// Create a new boot verifier with no registered keys, the given
    /// failure policy, and an **empty** [`RollbackFloor`].
    ///
    /// # Security warning
    ///
    /// A verifier created with `new` starts from
    /// [`RollbackFloor::EMPTY`]: rollback protection and key-rotation
    /// replay protection therefore do **not** survive a power cycle. For
    /// production use, restore the persisted floor with
    /// [`Self::new_persisted`] instead. `new` is appropriate only for
    /// first-ever provisioning, tests, or platforms with no rollback
    /// threat model.
    ///
    /// Use [`Self::register_pub_key`] to provision keys before calling
    /// [`Self::verify_boot_chain`].
    pub fn new(crypto: C, failure_policy: BootFailurePolicy) -> Self {
        Self::new_persisted(crypto, failure_policy, RollbackFloor::EMPTY)
    }

    /// Create a boot verifier whose rollback / anti-replay state is
    /// seeded from a [`RollbackFloor`] previously persisted to
    /// non-volatile storage.
    ///
    /// This is the constructor production firmware should use: it carries
    /// the downgrade floor, the anti-replay timestamp, and the key
    /// rotation counter across a power cycle. After a successful
    /// verification or key rotation, persist the updated floor via
    /// [`Self::floor_for_persistence`] so the next boot can restore it.
    pub fn new_persisted(
        crypto: C,
        failure_policy: BootFailurePolicy,
        floor: RollbackFloor,
    ) -> Self {
        Self {
            crypto,
            pub_keys: [[0u8; 65]; MAX_PUB_KEYS],
            registered_keys: 0,
            failure_policy,
            last_verified_timestamp: floor.last_verified_timestamp,
            stage_versions: floor.stage_versions,
            key_rotation_counter: floor.key_rotation_counter,
        }
    }

    /// Snapshot the current rollback / anti-replay state so the caller
    /// can persist it to non-volatile storage.
    ///
    /// Persist the returned value after every successful
    /// [`Self::verify_boot_chain`] and every successful
    /// [`Self::replace_pub_key_authorized`], and restore it on the next
    /// boot via [`Self::new_persisted`]. The floor is monotonic — never
    /// write back a value older than the last persisted one.
    pub fn floor_for_persistence(&self) -> RollbackFloor {
        RollbackFloor {
            last_verified_timestamp: self.last_verified_timestamp,
            stage_versions: self.stage_versions,
            key_rotation_counter: self.key_rotation_counter,
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

    /// The monotonic counter the next [`Self::replace_pub_key_authorized`]
    /// authorization signature must be bound to.
    ///
    /// A rotation authorizer signs a digest over this exact value (see
    /// [`Self::key_rotation_authorization_digest`]). After a successful
    /// rotation the counter is incremented, so the just-used signature can
    /// never be replayed. Persist the counter as part of
    /// [`Self::floor_for_persistence`].
    pub fn key_rotation_counter(&self) -> u64 {
        self.key_rotation_counter
    }

    /// Compute the 32-byte digest an authorizer must sign to rotate a key.
    ///
    /// The pre-image binds, in order:
    ///
    /// 1. [`KEY_ROTATION_AUTH_DOMAIN`] — 25-byte domain separation tag
    /// 2. `rotation_counter` as big-endian `u64` — 8 bytes (anti-replay)
    /// 3. `slot` as big-endian `u32` — 4 bytes (cross-slot binding)
    /// 4. `new_key` — 65 bytes
    ///
    /// `rotation_counter` MUST be the verifier's current
    /// [`Self::key_rotation_counter`] at signing time. Because the counter
    /// is monotonic and advanced on every successful rotation, a captured
    /// authorization signature is bound to a single counter value and
    /// cannot be replayed to re-apply a stale (possibly since-compromised)
    /// key.
    pub fn key_rotation_authorization_digest(
        slot: usize,
        new_key: &[u8; 65],
        rotation_counter: u64,
        crypto: &impl CryptoProvider,
    ) -> Result<[u8; 32], VsError> {
        // Pre-image: [domain(25) || counter_be_u64(8) || slot_be_u32(4) || key(65)]
        let mut digest_input = [0u8; 25 + 8 + 4 + 65];
        digest_input[..25].copy_from_slice(KEY_ROTATION_AUTH_DOMAIN);
        digest_input[25..33].copy_from_slice(&rotation_counter.to_be_bytes());
        digest_input[33..37].copy_from_slice(&(slot as u32).to_be_bytes());
        digest_input[37..].copy_from_slice(new_key);
        let mut digest = [0u8; 32];
        crypto.sha256(&digest_input, &mut digest)?;
        zeroize_buf(&mut digest_input);
        Ok(digest)
    }

    /// Replace a public key with authorization.
    ///
    /// Requires a valid signature from a **different** existing registered
    /// key over the rotation authorization digest (see
    /// [`Self::key_rotation_authorization_digest`]).
    ///
    /// # Anti-replay
    ///
    /// The signed digest binds the verifier's monotonic
    /// [`Self::key_rotation_counter`]. The authorizer must sign a digest
    /// computed with the counter's current value; on success the counter
    /// is advanced, permanently invalidating that signature. A rotation
    /// message captured off the wire therefore cannot be re-applied later
    /// to revert a slot to a previously-authorized key. Persist the
    /// updated [`Self::floor_for_persistence`] after a successful call so
    /// the counter survives a power cycle.
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
        // Reject self-authorization: a key must not authorize replacement
        // of *its own slot*. If the slot's current key is already
        // compromised, allowing it to sign its own rotation would let the
        // attacker keep control indefinitely. Rotation must be authorized
        // by a *different* registered key.
        if authorizing_key_id.get() as usize == slot {
            return Err(VsError::PolicyViolation);
        }
        // Verify that the authorizing key is registered
        let auth_idx = authorizing_key_id.get() as usize;
        if auth_idx >= MAX_PUB_KEYS || (self.registered_keys & (1 << auth_idx)) == 0 {
            return Err(VsError::AuthenticationFailure);
        }
        // Bind slot index AND the monotonic rotation counter into the
        // digest. The counter makes a captured authorization signature
        // single-use: replaying it after the counter has advanced fails.
        let digest = Self::key_rotation_authorization_digest(
            slot,
            new_key,
            self.key_rotation_counter,
            &self.crypto,
        )?;
        // Verify authorization signature
        let auth_key = &self.pub_keys[auth_idx];
        let verified = self
            .crypto
            .verify_p256(auth_key, &digest, authorization_sig)?;
        if !verified {
            return Err(VsError::AuthenticationFailure);
        }
        // Authorized - perform the replacement and advance the monotonic
        // anti-replay counter so this signature can never be reused.
        self.pub_keys[slot] = *new_key;
        self.registered_keys |= 1 << slot;
        self.key_rotation_counter = self.key_rotation_counter.saturating_add(1);
        Ok(())
    }

    /// Verify a boot chain. Returns attestation on success.
    ///
    /// Each boot stage extends a stage-specific PCR register and the
    /// chain hash is domain-separated. The `timestamp_us` must be
    /// strictly greater than the previous successful verification's
    /// timestamp to prevent replay.
    ///
    /// The chain MUST begin at [`BootStage::Bootloader`] and stages
    /// MUST be contiguous in `BootStage::ordinal`; skipping a stage
    /// (e.g. omitting `Hypervisor`) is rejected with
    /// [`VsError::PolicyViolation`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// use vs_secure_boot::{BootEntry, BootFailurePolicy, BootStage, BootVerifier};
    /// use vs_crypto::{CryptoProvider, KeyId};
    ///
    /// fn verify<C: CryptoProvider>(crypto: C, pub_key: &[u8; 65]) {
    ///     let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);
    ///     verifier.register_pub_key(KeyId(0), pub_key).unwrap();
    ///
    ///     let entries: &[BootEntry] = &[ /* signed bootloader, hypervisor, ... */ ];
    ///     let timestamp_us = 1_700_000_000_000_000;
    ///     let attestation = verifier.verify_boot_chain(entries, timestamp_us).unwrap();
    ///     let _ = attestation.chain_hash;
    /// }
    /// ```
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

        // The chain MUST begin at `BootStage::Bootloader`. A chain that
        // starts mid-way (e.g. at `Os` or an `Application`) implies the
        // earlier root-of-trust stages were never measured — that's a PCR
        // bypass and we reject it outright.
        if entries[0].stage != BootStage::Bootloader {
            return Err(VsError::PolicyViolation);
        }

        // Verify stages are strictly ordered AND contiguous in
        // `ordinal()`. Strictly-increasing alone allowed an attacker to
        // skip Hypervisor / Os and present `[Bootloader, Application(0)]`,
        // leaving the intermediate PCRs un-measured. Requiring
        // contiguous ordinals forces every expected stage to appear.
        for i in 1..entries.len() {
            let prev = entries[i - 1].stage.ordinal();
            let cur = entries[i].stage.ordinal();
            if cur <= prev {
                return Err(VsError::IntegrityFailure);
            }
            if cur != prev + 1 {
                // A stage was skipped (e.g. Bootloader -> Os omits
                // Hypervisor, or Os -> Application(1) omits Application(0)).
                return Err(VsError::PolicyViolation);
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

            // Verify signature against the stage-bound digest (wire format v2).
            // The signed pre-image includes the BootStage discriminant, so a
            // signature produced for stage N cannot be presented as stage M.
            // See `BootEntry::compute_signing_digest` for the exact encoding.
            let signing_digest =
                BootEntry::compute_signing_digest(entry.stage, &entry.image_hash, &self.crypto)?;
            let valid = self.crypto.verify_p256(
                &self.pub_keys[key_idx],
                &signing_digest,
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
    ///
    /// # Rollback memory on the report-and-continue path
    ///
    /// The rollback / anti-replay floor (`stage_versions`,
    /// `last_verified_timestamp`) is advanced **only** when
    /// [`Self::verify_boot_chain`] returns `Ok` — i.e. when the *entire*
    /// chain verified. When verification fails, the floor is left
    /// untouched even under [`BootFailurePolicy::ReportOnly`] or
    /// [`BootFailurePolicy::RequestRollback`].
    ///
    /// This is intentional and fail-closed: a chain that did not verify
    /// must not be allowed to raise the downgrade floor. But it means a
    /// `ReportOnly` deployment that boots a failed/old image anyway keeps
    /// **no record** that it did so — the next boot sees the same
    /// pre-failure floor. Callers that continue booting on failure must
    /// not assume any rollback state was recorded; if they need to track
    /// such boots they must do so out of band.
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

    /// Test helper: produce a stage-bound signature for a boot entry
    /// using wire format v2 (stage discriminant included in the signed
    /// payload). Mirrors what production callers do via `BootEntry::sign`.
    fn sign_image(
        crypto: &SoftwareCryptoProvider,
        stage: BootStage,
        image_hash: &[u8; 32],
    ) -> [u8; 64] {
        BootEntry::sign(stage, image_hash, KeyId(0), crypto).unwrap()
    }

    fn sign_image_with_key(
        crypto: &SoftwareCryptoProvider,
        stage: BootStage,
        image_hash: &[u8; 32],
        key_id: KeyId,
    ) -> [u8; 64] {
        BootEntry::sign(stage, image_hash, key_id, crypto).unwrap()
    }

    // ---- Boot chain verification ----

    #[test]
    fn valid_boot_chain() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let h1 = [1u8; 32];
        let h_hyp = [3u8; 32];
        let h2 = [2u8; 32];
        let s1 = sign_image(&crypto, BootStage::Bootloader, &h1);
        let s_hyp = sign_image(&crypto, BootStage::Hypervisor, &h_hyp);
        let s2 = sign_image(&crypto, BootStage::Os, &h2);

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
                image_hash: h_hyp,
                signature: s_hyp,
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
        assert_ne!(att.pcr_snapshot[1], [0u8; 32]); // Hypervisor PCR extended
        assert_ne!(att.pcr_snapshot[2], [0u8; 32]); // Os PCR extended
        assert_eq!(att.pcr_snapshot[3], [0u8; 32]); // App(0) PCR untouched
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
        let s = sign_image(&crypto, BootStage::Bootloader, &h);

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
        let h_hyp = [0xAA; 32];
        let h2 = [2u8; 32];
        // Build a chain that is contiguous through Bootloader -> Hypervisor
        // -> Os, then reverses ordinal order by re-presenting Hypervisor.
        // This isolates the strictly-monotonic-ordinal check (a non-skip
        // out-of-order violation) so we observe `IntegrityFailure` rather
        // than the contiguity (`PolicyViolation`) check firing first.
        let s1 = sign_image(&crypto, BootStage::Bootloader, &h1);
        let s_hyp = sign_image(&crypto, BootStage::Hypervisor, &h_hyp);
        let s2 = sign_image(&crypto, BootStage::Os, &h2);

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
                image_hash: h_hyp,
                signature: s_hyp,
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
            BootEntry {
                stage: BootStage::Hypervisor,
                image_hash: h_hyp,
                signature: s_hyp,
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
        let s = sign_image(&crypto, BootStage::Bootloader, &h);

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
        let s = sign_image(&crypto, BootStage::Bootloader, &h);

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
        let s_a = sign_image(&crypto, BootStage::Bootloader, &h_a);
        let s_b = sign_image(&crypto, BootStage::Bootloader, &h_b);

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
        let s = sign_image(&crypto, BootStage::Bootloader, &h);

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
        let s1 = sign_image(&crypto, BootStage::Bootloader, &h1);
        let s2 = sign_image(&crypto, BootStage::Hypervisor, &h2);
        let s3 = sign_image(&crypto, BootStage::Os, &h3);
        let s4 = sign_image(&crypto, BootStage::Application(0), &h4);

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
        let h_hyp = [0x15; 32];
        let h2 = [0x20; 32];
        // Use stage-bound v2 signing for each entry's declared stage.
        // Chain must be contiguous: Bootloader -> Hypervisor -> Os.
        let s1 = sign_image_with_key(&crypto, BootStage::Bootloader, &h1, KeyId(0));
        let s_hyp = sign_image_with_key(&crypto, BootStage::Hypervisor, &h_hyp, KeyId(0));
        let s2 = sign_image_with_key(&crypto, BootStage::Os, &h2, KeyId(1));

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
                stage: BootStage::Hypervisor,
                image_hash: h_hyp,
                signature: s_hyp,
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
        // Selection must be non-zero — empty selection is rejected.
        let q_a = tpm_a.quote(1, &nonce).unwrap();
        let q_b = tpm_b.quote(1, &nonce).unwrap();
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
        let s = sign_image(&crypto, BootStage::Bootloader, &h);

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
        let s = sign_image(&crypto, BootStage::Bootloader, &h);

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
        let h_boot = [0x10; 32];
        let h_hyp = [0x11; 32];
        let h_os = [0x12; 32];
        let h_app = [0xAA; 32];
        // h_app is used by both Application(0) and Application(1) entries
        // below. Each verifier sees a chain with one of those app variants,
        // so we must produce a stage-bound signature for each variant
        // separately. The chain must be contiguous: Bootloader, Hypervisor,
        // Os, Application(0|1).
        let s_boot = sign_image(&crypto, BootStage::Bootloader, &h_boot);
        let s_hyp = sign_image(&crypto, BootStage::Hypervisor, &h_hyp);
        let s_os = sign_image(&crypto, BootStage::Os, &h_os);
        let s_app0 = sign_image(&crypto, BootStage::Application(0), &h_app);
        let s_app1 = sign_image(&crypto, BootStage::Application(1), &h_app);

        let mut v1 = BootVerifier::new(test_crypto(), BootFailurePolicy::Halt);
        let mut v2 = BootVerifier::new(test_crypto(), BootFailurePolicy::Halt);
        v1.register_pub_key(KeyId(0), &pk).unwrap();
        v2.register_pub_key(KeyId(0), &pk).unwrap();

        let boot = BootEntry {
            stage: BootStage::Bootloader,
            image_hash: h_boot,
            signature: s_boot,
            signer_key_id: KeyId(0),
            version: 1,
        };
        let hyp = BootEntry {
            stage: BootStage::Hypervisor,
            image_hash: h_hyp,
            signature: s_hyp,
            signer_key_id: KeyId(0),
            version: 1,
        };
        let os = BootEntry {
            stage: BootStage::Os,
            image_hash: h_os,
            signature: s_os,
            signer_key_id: KeyId(0),
            version: 1,
        };

        let chain1 = [
            boot,
            hyp,
            os,
            BootEntry {
                stage: BootStage::Application(0),
                image_hash: h_app,
                signature: s_app0,
                signer_key_id: KeyId(0),
                version: 1,
            },
        ];
        // Application(1) chain must include Application(0) to be contiguous.
        let s_app0_chain2 = sign_image(&crypto, BootStage::Application(0), &h_boot);
        let chain2 = [
            boot,
            hyp,
            os,
            BootEntry {
                stage: BootStage::Application(0),
                image_hash: h_boot,
                signature: s_app0_chain2,
                signer_key_id: KeyId(0),
                version: 1,
            },
            BootEntry {
                stage: BootStage::Application(1),
                image_hash: h_app,
                signature: s_app1,
                signer_key_id: KeyId(0),
                version: 1,
            },
        ];

        let att1 = v1.verify_boot_chain(&chain1, 1000).unwrap();
        let att2 = v2.verify_boot_chain(&chain2, 1000).unwrap();
        // PCR 3 should differ because app IDs are mixed in (chain1's
        // Application(0) uses h_app whereas chain2's Application(0) uses
        // h_boot — distinct measurements).
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

    // ---- BootEntry signature: stage binding (wire format v2) ----

    /// Same-stage roundtrip: signing as Bootloader and verifying as
    /// Bootloader must succeed via both `BootEntry::verify` and the
    /// full `BootVerifier::verify_boot_chain` path.
    #[test]
    fn boot_entry_sign_verify_same_stage_roundtrip() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let h = [0x77; 32];

        let sig = BootEntry::sign(BootStage::Bootloader, &h, KeyId(0), &crypto).unwrap();
        let entry = BootEntry {
            stage: BootStage::Bootloader,
            image_hash: h,
            signature: sig,
            signer_key_id: KeyId(0),
            version: 1,
        };

        // Direct verify on the entry.
        assert!(entry.verify(&pk, &crypto).unwrap());

        // Full chain verification path.
        let mut verifier = BootVerifier::new(test_crypto(), BootFailurePolicy::Halt);
        verifier.register_pub_key(KeyId(0), &pk).unwrap();
        verifier.verify_boot_chain(&[entry], 1).unwrap();
    }

    /// Cross-stage substitution attack must FAIL.
    ///
    /// Sign a payload as `BootStage::Bootloader`, then attempt to present
    /// the resulting entry under `BootStage::Application(0)`. Verification
    /// must reject because the stage is now bound into the signed digest
    /// (wire format v2). Pre-fix, this attack would have succeeded.
    #[test]
    fn boot_entry_cross_stage_substitution_rejected() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let h = [0x77; 32];

        // Sign for Bootloader.
        let sig = BootEntry::sign(BootStage::Bootloader, &h, KeyId(0), &crypto).unwrap();

        // Attacker presents the entry as Application(0) with the same hash + sig.
        let forged = BootEntry {
            stage: BootStage::Application(0),
            image_hash: h,
            signature: sig,
            signer_key_id: KeyId(0),
            version: 1,
        };

        // Direct verify should reject (Ok(false), not Err).
        assert!(!forged.verify(&pk, &crypto).unwrap());

        // BootVerifier path should reject the cross-stage substitution
        // with `AuthenticationFailure`. We embed the forged entry inside an
        // otherwise valid `[Bootloader, Hypervisor, Os, Application(0)]`
        // chain prefix so that the per-entry signature check is what fires
        // (rather than the earlier structural checks for empty / wrong
        // start / stage-skip, which would mask the signature-binding test).
        let h_boot = [0x10; 32];
        let h_hyp = [0x11; 32];
        let h_os = [0x12; 32];
        let s_boot = sign_image(&crypto, BootStage::Bootloader, &h_boot);
        let s_hyp = sign_image(&crypto, BootStage::Hypervisor, &h_hyp);
        let s_os = sign_image(&crypto, BootStage::Os, &h_os);

        let mut verifier = BootVerifier::new(test_crypto(), BootFailurePolicy::Halt);
        verifier.register_pub_key(KeyId(0), &pk).unwrap();
        let entries = [
            BootEntry {
                stage: BootStage::Bootloader,
                image_hash: h_boot,
                signature: s_boot,
                signer_key_id: KeyId(0),
                version: 1,
            },
            BootEntry {
                stage: BootStage::Hypervisor,
                image_hash: h_hyp,
                signature: s_hyp,
                signer_key_id: KeyId(0),
                version: 1,
            },
            BootEntry {
                stage: BootStage::Os,
                image_hash: h_os,
                signature: s_os,
                signer_key_id: KeyId(0),
                version: 1,
            },
            forged,
        ];
        assert_eq!(
            verifier.verify_boot_chain(&entries, 1),
            Err(VsError::AuthenticationFailure),
        );
    }

    /// Reverse direction: signature produced for Application(0) must not
    /// verify when presented as Bootloader.
    #[test]
    fn boot_entry_cross_stage_substitution_rejected_reverse() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let h = [0xC3; 32];

        let sig = BootEntry::sign(BootStage::Application(0), &h, KeyId(0), &crypto).unwrap();
        let forged = BootEntry {
            stage: BootStage::Bootloader,
            image_hash: h,
            signature: sig,
            signer_key_id: KeyId(0),
            version: 1,
        };
        assert!(!forged.verify(&pk, &crypto).unwrap());
    }

    /// Different application indices must not be interchangeable either.
    /// Signing for Application(0) and presenting as Application(1) must fail.
    #[test]
    fn boot_entry_cross_app_index_substitution_rejected() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let h = [0xA1; 32];

        let sig = BootEntry::sign(BootStage::Application(0), &h, KeyId(0), &crypto).unwrap();
        let forged = BootEntry {
            stage: BootStage::Application(1),
            image_hash: h,
            signature: sig,
            signer_key_id: KeyId(0),
            version: 1,
        };
        assert!(!forged.verify(&pk, &crypto).unwrap());
    }

    /// The signing digest must depend on the stage: digests for the same
    /// `image_hash` under different stages must differ.
    #[test]
    fn signing_digest_differs_per_stage() {
        let crypto = test_crypto();
        let h = [0x55; 32];
        let d_boot = BootEntry::compute_signing_digest(BootStage::Bootloader, &h, &crypto).unwrap();
        let d_hyp = BootEntry::compute_signing_digest(BootStage::Hypervisor, &h, &crypto).unwrap();
        let d_os = BootEntry::compute_signing_digest(BootStage::Os, &h, &crypto).unwrap();
        let d_app0 =
            BootEntry::compute_signing_digest(BootStage::Application(0), &h, &crypto).unwrap();
        let d_app1 =
            BootEntry::compute_signing_digest(BootStage::Application(1), &h, &crypto).unwrap();

        assert_ne!(d_boot, d_hyp);
        assert_ne!(d_boot, d_os);
        assert_ne!(d_boot, d_app0);
        assert_ne!(d_app0, d_app1);
        assert_ne!(d_hyp, d_os);
    }

    /// Sanity: the wire-format version constant exists and equals 2.
    #[test]
    fn boot_entry_signature_version_is_v2() {
        assert_eq!(BOOT_ENTRY_SIGNATURE_VERSION, 2);
    }

    // ---- PCR-skip / stage-contiguity enforcement ----

    /// A chain that skips the Hypervisor stage (Bootloader -> Os) must be
    /// rejected. Pre-fix, the verifier only required strictly-increasing
    /// ordinals and accepted such chains, leaving PCR 1 un-measured.
    #[test]
    fn chain_skipping_hypervisor_rejected() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let h_boot = [0x10; 32];
        let h_os = [0x20; 32];
        let s_boot = sign_image(&crypto, BootStage::Bootloader, &h_boot);
        let s_os = sign_image(&crypto, BootStage::Os, &h_os);

        let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);
        verifier.register_pub_key(KeyId(0), &pk).unwrap();

        let entries = [
            BootEntry {
                stage: BootStage::Bootloader,
                image_hash: h_boot,
                signature: s_boot,
                signer_key_id: KeyId(0),
                version: 1,
            },
            BootEntry {
                stage: BootStage::Os,
                image_hash: h_os,
                signature: s_os,
                signer_key_id: KeyId(0),
                version: 1,
            },
        ];
        assert_eq!(
            verifier.verify_boot_chain(&entries, 1),
            Err(VsError::PolicyViolation),
        );
    }

    /// A chain that does not begin at `Bootloader` must be rejected even
    /// if its stages are otherwise contiguous.
    #[test]
    fn chain_not_starting_at_bootloader_rejected() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let h_hyp = [0x11; 32];
        let h_os = [0x12; 32];
        let s_hyp = sign_image(&crypto, BootStage::Hypervisor, &h_hyp);
        let s_os = sign_image(&crypto, BootStage::Os, &h_os);

        let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);
        verifier.register_pub_key(KeyId(0), &pk).unwrap();

        let entries = [
            BootEntry {
                stage: BootStage::Hypervisor,
                image_hash: h_hyp,
                signature: s_hyp,
                signer_key_id: KeyId(0),
                version: 1,
            },
            BootEntry {
                stage: BootStage::Os,
                image_hash: h_os,
                signature: s_os,
                signer_key_id: KeyId(0),
                version: 1,
            },
        ];
        assert_eq!(
            verifier.verify_boot_chain(&entries, 1),
            Err(VsError::PolicyViolation),
        );
    }

    /// Skipping an application index (Application(0) -> Application(2))
    /// is also a contiguity violation and must be rejected.
    #[test]
    fn chain_skipping_application_index_rejected() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let h_boot = [0x10; 32];
        let h_hyp = [0x11; 32];
        let h_os = [0x12; 32];
        let h_app0 = [0x13; 32];
        let h_app2 = [0x14; 32];
        let s_boot = sign_image(&crypto, BootStage::Bootloader, &h_boot);
        let s_hyp = sign_image(&crypto, BootStage::Hypervisor, &h_hyp);
        let s_os = sign_image(&crypto, BootStage::Os, &h_os);
        let s_app0 = sign_image(&crypto, BootStage::Application(0), &h_app0);
        let s_app2 = sign_image(&crypto, BootStage::Application(2), &h_app2);

        let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);
        verifier.register_pub_key(KeyId(0), &pk).unwrap();

        let entries = [
            BootEntry {
                stage: BootStage::Bootloader,
                image_hash: h_boot,
                signature: s_boot,
                signer_key_id: KeyId(0),
                version: 1,
            },
            BootEntry {
                stage: BootStage::Hypervisor,
                image_hash: h_hyp,
                signature: s_hyp,
                signer_key_id: KeyId(0),
                version: 1,
            },
            BootEntry {
                stage: BootStage::Os,
                image_hash: h_os,
                signature: s_os,
                signer_key_id: KeyId(0),
                version: 1,
            },
            BootEntry {
                stage: BootStage::Application(0),
                image_hash: h_app0,
                signature: s_app0,
                signer_key_id: KeyId(0),
                version: 1,
            },
            BootEntry {
                stage: BootStage::Application(2),
                image_hash: h_app2,
                signature: s_app2,
                signer_key_id: KeyId(0),
                version: 1,
            },
        ];
        assert_eq!(
            verifier.verify_boot_chain(&entries, 1),
            Err(VsError::PolicyViolation),
        );
    }

    // ---- Self-authorized key replacement rejected ----

    /// A key MUST NOT be able to authorize the replacement of its own
    /// slot. If the slot's key is compromised, allowing it to self-sign
    /// rotation lets the attacker keep control. Rotation must be
    /// authorized by a *different* registered key.
    #[test]
    fn replace_pub_key_rejects_self_authorization() {
        let crypto = test_crypto();
        let pk = test_pub_key();
        let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);
        verifier.register_pub_key(KeyId(0), &pk).unwrap();

        // Even with a *valid* signature, self-authorization must be
        // rejected before any signature check is performed.
        let new_key = [0x04u8; 65];
        let dummy_sig = [0u8; 64];
        assert_eq!(
            verifier.replace_pub_key_authorized(0, &new_key, KeyId::new(0), &dummy_sig),
            Err(VsError::PolicyViolation),
        );
    }

    /// Authorized key rotation with a valid counter-bound signature
    /// succeeds and advances the monotonic rotation counter.
    #[test]
    fn replace_pub_key_authorized_success_and_counter_advances() {
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

        // Pre-compute the counter-0-bound authorization signature using a
        // standalone crypto handle (same key material as the verifier's).
        let new_key = [0x07u8; 65];
        let signer = {
            let mut s = SoftwareCryptoProvider::default();
            s.set_key(KeyId(0), &key_a).unwrap();
            s.set_key(KeyId(1), &key_b).unwrap();
            s
        };
        let digest = BootVerifier::<SoftwareCryptoProvider>::key_rotation_authorization_digest(
            0, &new_key, 0, &signer,
        )
        .unwrap();
        let mut sig = [0u8; 64];
        signer.sign_p256(KeyId(1), &digest, &mut sig).unwrap();

        let mut verifier = BootVerifier::new(crypto, BootFailurePolicy::Halt);
        verifier.register_pub_key(KeyId(0), &pk_a).unwrap();
        verifier.register_pub_key(KeyId(1), &pk_b).unwrap();
        assert_eq!(verifier.key_rotation_counter(), 0);

        verifier
            .replace_pub_key_authorized(0, &new_key, KeyId(1), &sig)
            .unwrap();
        assert_eq!(verifier.key_rotation_counter(), 1);

        // The same signature is now stale: it is bound to counter 0 but
        // the verifier expects counter 1. Replay must be rejected.
        assert_eq!(
            verifier.replace_pub_key_authorized(0, &new_key, KeyId(1), &sig),
            Err(VsError::AuthenticationFailure),
        );
    }

    /// The rotation counter is seeded from a persisted [`RollbackFloor`],
    /// so a captured signature bound to a pre-reboot counter value cannot
    /// be replayed after the verifier is restored on the next boot.
    #[test]
    fn key_rotation_counter_survives_persistence() {
        let crypto = test_crypto();
        let floor = RollbackFloor {
            last_verified_timestamp: Some(500),
            stage_versions: [0; PCR_COUNT],
            key_rotation_counter: 9,
        };
        let verifier =
            BootVerifier::new_persisted(crypto, BootFailurePolicy::Halt, floor);
        assert_eq!(verifier.key_rotation_counter(), 9);
        assert_eq!(verifier.floor_for_persistence(), floor);
    }

    // ---- Empty PCR selection rejected ----

    /// `SoftwareTpm::quote` with an empty (zero) PCR selection must be
    /// rejected. Otherwise the TPM would emit a "quote" attesting to no
    /// PCR state at all.
    #[test]
    fn software_tpm_quote_rejects_empty_selection() {
        let tpm = SoftwareTpm::new(test_crypto());
        let nonce = [0u8; 32];
        assert_eq!(tpm.quote(0, &nonce), Err(VsError::InvalidInput));
    }

    /// `HardwareTpm::quote` must likewise reject `selection == 0`.
    #[test]
    fn hardware_tpm_quote_rejects_empty_selection() {
        let mut crypto = SoftwareCryptoProvider::default();
        crypto.set_key(KeyId(0), &[0x42; 32]).unwrap();
        let tpm = HardwareTpm::new(crypto, KeyId(0));
        let nonce = [0u8; 32];
        assert_eq!(tpm.quote(0, &nonce), Err(VsError::InvalidInput));
    }
}
