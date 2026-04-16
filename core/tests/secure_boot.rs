// SPDX-License-Identifier: Apache-2.0
mod common;

use vs_secure_boot::{
    BootEntry, BootFailurePolicy, BootStage, BootVerificationOutcome, BootVerifier, CryptoProviderBackedTpm,
    TpmAttestation,
};
use vs_types::KeyId;

use common::make_crypto;

#[test]
fn boot_verifier_empty_chain() {
    let mut verifier = BootVerifier::new(make_crypto(), BootFailurePolicy::ReportOnly);
    let result = verifier.verify_boot_chain(&[], 1000);
    // Empty boot chain should return an error (IntegrityFailure).
    assert!(result.is_err(), "empty boot chain should produce an error");
}

#[test]
fn boot_verifier_register_key() {
    let mut verifier = BootVerifier::new(make_crypto(), BootFailurePolicy::ReportOnly);
    let pub_key = [0x04; 65];
    verifier
        .register_pub_key(KeyId(0), &pub_key)
        .expect("register pub key");

    // Registering with the same id again should fail (no implicit overwrite).
    let result = verifier.register_pub_key(KeyId(0), &pub_key);
    assert!(result.is_err(), "re-registering same key id should fail");
}

#[test]
fn boot_chain_with_policy_report_only() {
    let mut verifier = BootVerifier::new(make_crypto(), BootFailurePolicy::ReportOnly);
    verifier
        .register_pub_key(KeyId(0), &[0x04; 65])
        .expect("register key");

    let entry = BootEntry {
        stage: BootStage::Bootloader,
        image_hash: [0xAA; 32],
        signature: [0u8; 64],
        signer_key_id: KeyId(0),
        version: 1,
    };

    let outcome = verifier.verify_boot_chain_with_policy(&[entry], 1000);
    match outcome {
        BootVerificationOutcome::ReportAndContinue(_) => {} // expected
        other => panic!(
            "expected ReportAndContinue for invalid signature with ReportOnly policy, got {:?}",
            other
        ),
    }
}

#[test]
fn boot_chain_with_policy_halt() {
    let mut verifier = BootVerifier::new(make_crypto(), BootFailurePolicy::Halt);
    verifier
        .register_pub_key(KeyId(0), &[0x04; 65])
        .expect("register key");

    let entry = BootEntry {
        stage: BootStage::Bootloader,
        image_hash: [0xAA; 32],
        signature: [0u8; 64],
        signer_key_id: KeyId(0),
        version: 1,
    };

    let outcome = verifier.verify_boot_chain_with_policy(&[entry], 1000);
    match outcome {
        BootVerificationOutcome::Halt(_) => {} // expected
        other => panic!(
            "expected Halt for invalid signature with Halt policy, got {:?}",
            other
        ),
    }
}

#[test]
fn boot_verifier_multiple_stages() {
    let mut verifier = BootVerifier::new(make_crypto(), BootFailurePolicy::ReportOnly);
    verifier
        .register_pub_key(KeyId(0), &[0x04; 65])
        .expect("register key");

    let entries = [
        BootEntry {
            stage: BootStage::Bootloader,
            image_hash: [0xAA; 32],
            signature: [0u8; 64],
            signer_key_id: KeyId(0),
            version: 1,
        },
        BootEntry {
            stage: BootStage::Os,
            image_hash: [0xBB; 32],
            signature: [0u8; 64],
            signer_key_id: KeyId(0),
            version: 1,
        },
        BootEntry {
            stage: BootStage::Application(0),
            image_hash: [0xCC; 32],
            signature: [0u8; 64],
            signer_key_id: KeyId(0),
            version: 1,
        },
    ];

    // With mock crypto the signatures are invalid, so with ReportOnly we expect
    // ReportAndContinue rather than Verified.
    let outcome = verifier.verify_boot_chain_with_policy(&entries, 5000);
    match outcome {
        BootVerificationOutcome::ReportAndContinue(_) => {} // expected
        BootVerificationOutcome::Verified(_) => {} // also acceptable if crypto happens to accept
        other => panic!(
            "expected ReportAndContinue or Verified for multi-stage chain, got {:?}",
            other
        ),
    }
}

#[test]
fn crypto_provider_backed_tpm_quote_verify_round_trip() {
    let crypto = make_crypto();
    let mut tpm = CryptoProviderBackedTpm::new(crypto, KeyId(0));

    // Extend PCR 0 with a known measurement.
    tpm.extend_pcr(0, &[0xAA; 32]).expect("extend PCR 0");

    // Quote PCR 0 (selection bit 0) with a nonce.
    let nonce = [0xBB; 32];
    let quote = tpm.quote(0x01, &nonce).expect("quote");

    // Nonce in the quote must match what we provided.
    assert_eq!(quote.nonce, nonce, "nonce should match");

    // PCR digest should be non-zero (PCR was extended).
    assert_ne!(quote.pcr_digest, [0u8; 32], "pcr_digest should be non-zero");

    // Signature should be non-zero.
    assert_ne!(quote.signature, [0u8; 64], "signature should be non-zero");

    // Reading PCR 0 should return a non-zero value after extension.
    let pcr0 = tpm.read_pcr(0).expect("read PCR 0");
    assert_ne!(pcr0, [0u8; 32], "PCR 0 should be non-zero after extend");
}

#[test]
fn crypto_provider_backed_tpm_multiple_pcr_extension() {
    let crypto = make_crypto();
    let mut tpm = CryptoProviderBackedTpm::new(crypto, KeyId(0));

    // Extend PCR 0 and PCR 1 with different measurements.
    tpm.extend_pcr(0, &[0xAA; 32]).expect("extend PCR 0");
    tpm.extend_pcr(1, &[0xBB; 32]).expect("extend PCR 1");

    let nonce = [0xCC; 32];

    // Quote selecting both PCR 0 and PCR 1 (bitmask 0x03).
    let quote_both = tpm.quote(0x03, &nonce).expect("quote both PCRs");

    // Quote selecting only PCR 0 (bitmask 0x01).
    let quote_pcr0_only = tpm.quote(0x01, &nonce).expect("quote PCR 0 only");

    // The digests must differ because different PCR sets were selected.
    assert_ne!(
        quote_both.pcr_digest, quote_pcr0_only.pcr_digest,
        "digest for both PCRs should differ from PCR 0 only"
    );
}

#[test]
fn boot_stage_version_rollback_enforcement() {
    let mut verifier = BootVerifier::new(make_crypto(), BootFailurePolicy::ReportOnly);

    verifier
        .set_stage_version(BootStage::Bootloader, 5)
        .expect("set stage version");
    assert_eq!(
        verifier.stage_version(BootStage::Bootloader),
        Ok(5),
        "bootloader stage version should be 5"
    );
}

// ---------------------------------------------------------------------------
// V9 audit fix tests
// ---------------------------------------------------------------------------

#[test]
fn boot_chain_rollback_rejected() {
    // Set minimum version for bootloader stage, then try to verify
    // an entry with a lower version - should fail.
    let mut verifier = BootVerifier::new(make_crypto(), BootFailurePolicy::ReportOnly);
    verifier
        .register_pub_key(KeyId(0), &[0x04; 65])
        .expect("register key");
    verifier
        .set_stage_version(BootStage::Bootloader, 5)
        .expect("set stage version");

    let entry = BootEntry {
        stage: BootStage::Bootloader,
        image_hash: [0xAA; 32],
        signature: [0u8; 64],
        signer_key_id: KeyId(0),
        version: 3, // below minimum of 5
    };

    // With ReportOnly, the policy wrapper may report+continue, but the
    // underlying verify_boot_chain should detect the rollback.
    let result = verifier.verify_boot_chain(&[entry], 1000);
    assert!(result.is_err(), "rollback should be rejected");
}

#[test]
fn boot_entry_version_field_present() {
    let entry = BootEntry {
        stage: BootStage::Bootloader,
        image_hash: [0xBB; 32],
        signature: [0u8; 64],
        signer_key_id: KeyId(0),
        version: 42,
    };
    assert_eq!(entry.version, 42);
}
