// SPDX-License-Identifier: Apache-2.0
//! TUF canonical JSON parsing via `serde-json-core`.
//!
//! Parses TUF root metadata and signed metadata from canonical JSON byte
//! slices into the existing runtime types ([`TufRoot`], [`SignedMetadata`],
//! etc.). All parsing is zero-allocation, `#![no_std]` compatible, and
//! operates directly on `&[u8]` input.
//!
//! This module is only available when the `json` feature is enabled.

use serde::Deserialize;
use vs_types::VsError;

use crate::{
    KeyType, SignedMetadata, TufKey, TufSignature, TufSnapshot, TufTargetEntry, TufTargets,
    TufTimestamp,
};
use vs_crypto::CryptoProvider;

// ---------------------------------------------------------------------------
// Hex decoding (inline, no_std)
// ---------------------------------------------------------------------------

fn hex_nibble(b: u8) -> Result<u8, VsError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(VsError::InvalidInput),
    }
}

/// Decode a hex string into `out`. Returns an error if `hex` is not exactly
/// `2 * out.len()` characters or contains non-hex characters.
fn hex_decode(hex: &str, out: &mut [u8]) -> Result<(), VsError> {
    let bytes = hex.as_bytes();
    if bytes.len() != out.len() * 2 {
        return Err(VsError::InvalidInput);
    }
    let mut i = 0;
    while i < out.len() {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Intermediate serde types (zero-copy from JSON slice)
// ---------------------------------------------------------------------------

/// JSON representation of a TUF key.
#[derive(Deserialize)]
struct JsonKey<'a> {
    keyid: &'a str,
    keytype: &'a str,
    keyval: JsonKeyVal<'a>,
}

#[derive(Deserialize)]
struct JsonKeyVal<'a> {
    public: &'a str,
}

/// JSON representation of a TUF signature.
#[derive(Deserialize)]
struct JsonSignature<'a> {
    keyid: &'a str,
    sig: &'a str,
}

/// JSON representation of the `signed` portion of TUF root metadata.
#[derive(Deserialize)]
struct JsonRootSigned<'a> {
    version: u32,
    expires_us: u64,
    threshold: u8,
    #[serde(borrow)]
    keys: JsonKeyArray<'a>,
    // Per-role delegation keys (optional).
    #[serde(borrow)]
    targets_keys: Option<JsonKeyArray<'a>>,
    targets_threshold: Option<u8>,
    #[serde(borrow)]
    snapshot_keys: Option<JsonKeyArray<'a>>,
    snapshot_threshold: Option<u8>,
    #[serde(borrow)]
    timestamp_keys: Option<JsonKeyArray<'a>>,
    timestamp_threshold: Option<u8>,
}

/// Fixed-capacity array of up to 4 keys.
#[derive(Deserialize)]
struct JsonKeyArray<'a>(
    #[serde(borrow)] Option<JsonKey<'a>>,
    #[serde(borrow)] Option<JsonKey<'a>>,
    #[serde(borrow)] Option<JsonKey<'a>>,
    #[serde(borrow)] Option<JsonKey<'a>>,
);

/// Top-level signed root JSON envelope.
#[derive(Deserialize)]
struct JsonSignedRoot<'a> {
    #[serde(borrow)]
    signatures: JsonSigArray<'a>,
    #[serde(borrow)]
    signed: JsonRootSigned<'a>,
}

/// Fixed-capacity array of up to 4 signatures.
#[derive(Deserialize)]
struct JsonSigArray<'a>(
    #[serde(borrow)] Option<JsonSignature<'a>>,
    #[serde(borrow)] Option<JsonSignature<'a>>,
    #[serde(borrow)] Option<JsonSignature<'a>>,
    #[serde(borrow)] Option<JsonSignature<'a>>,
);

/// Top-level signed metadata JSON envelope (non-root roles).
#[derive(Deserialize)]
struct JsonSignedMetadata<'a> {
    #[serde(borrow)]
    signatures: JsonSigArray<'a>,
    version: u32,
    expires_us: u64,
    content_hash: &'a str,
}

// -- Delegation metadata serde types --------------------------------------

/// JSON representation of TUF timestamp metadata.
#[derive(Deserialize)]
struct JsonTimestamp<'a> {
    version: u32,
    expires_us: u64,
    snapshot_version: u32,
    snapshot_hash: &'a str,
}

/// JSON representation of TUF snapshot metadata.
#[derive(Deserialize)]
struct JsonSnapshot<'a> {
    version: u32,
    expires_us: u64,
    targets_version: u32,
    targets_hash: &'a str,
}

/// JSON representation of a single target entry.
#[derive(Deserialize)]
struct JsonTargetEntry<'a> {
    hash: &'a str,
    length: u64,
    target_id: &'a str,
}

/// Fixed-capacity array of up to 8 target entries.
#[derive(Deserialize)]
struct JsonTargetEntryArray<'a>(
    #[serde(borrow)] Option<JsonTargetEntry<'a>>,
    #[serde(borrow)] Option<JsonTargetEntry<'a>>,
    #[serde(borrow)] Option<JsonTargetEntry<'a>>,
    #[serde(borrow)] Option<JsonTargetEntry<'a>>,
    #[serde(borrow)] Option<JsonTargetEntry<'a>>,
    #[serde(borrow)] Option<JsonTargetEntry<'a>>,
    #[serde(borrow)] Option<JsonTargetEntry<'a>>,
    #[serde(borrow)] Option<JsonTargetEntry<'a>>,
);

/// JSON representation of TUF targets metadata.
#[derive(Deserialize)]
struct JsonTargetsSigned<'a> {
    version: u32,
    expires_us: u64,
    #[serde(borrow)]
    targets: JsonTargetEntryArray<'a>,
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

fn convert_key(jk: &JsonKey<'_>) -> Result<TufKey, VsError> {
    // TUF spec mandates the on-wire key type string `"ecdsa-sha2-nistp256"`
    // for NIST P-256 ECDSA. Earlier revisions of this parser accepted the
    // lax aliases `"ecdsa"` and `"EcdsaP256"`; both are rejected as of
    // v0.7.0 to remove wire-format ambiguity.
    let key_type = match jk.keytype {
        "ecdsa-sha2-nistp256" => KeyType::EcdsaP256,
        _ => return Err(VsError::InvalidInput),
    };

    let mut key_id = [0u8; 32];
    hex_decode(jk.keyid, &mut key_id)?;

    let mut public_key = [0u8; 65];
    hex_decode(jk.keyval.public, &mut public_key)?;

    Ok(TufKey {
        key_id,
        key_type,
        public_key,
    })
}

fn convert_sig(js: &JsonSignature<'_>) -> Result<TufSignature, VsError> {
    let mut key_id = [0u8; 32];
    hex_decode(js.keyid, &mut key_id)?;

    let mut sig = [0u8; 64];
    hex_decode(js.sig, &mut sig)?;

    Ok(TufSignature { key_id, sig })
}

fn convert_key_option(opt: &Option<JsonKey<'_>>) -> Result<Option<TufKey>, VsError> {
    match opt {
        Some(jk) => Ok(Some(convert_key(jk)?)),
        None => Ok(None),
    }
}

fn convert_sig_option(opt: &Option<JsonSignature<'_>>) -> Result<Option<TufSignature>, VsError> {
    match opt {
        Some(js) => Ok(Some(convert_sig(js)?)),
        None => Ok(None),
    }
}

fn convert_key_array(ka: &JsonKeyArray<'_>) -> Result<[Option<TufKey>; 4], VsError> {
    Ok([
        convert_key_option(&ka.0)?,
        convert_key_option(&ka.1)?,
        convert_key_option(&ka.2)?,
        convert_key_option(&ka.3)?,
    ])
}

fn convert_target_entry(jte: &JsonTargetEntry<'_>) -> Result<TufTargetEntry, VsError> {
    let mut hash = [0u8; 32];
    hex_decode(jte.hash, &mut hash)?;

    let id_bytes = jte.target_id.as_bytes();
    if id_bytes.len() > 32 {
        return Err(VsError::InvalidInput);
    }
    let mut target_id = [0u8; 32];
    target_id[..id_bytes.len()].copy_from_slice(id_bytes);

    Ok(TufTargetEntry {
        hash,
        length: jte.length,
        target_id,
        target_id_len: id_bytes.len() as u8,
    })
}

fn convert_target_entry_option(
    opt: &Option<JsonTargetEntry<'_>>,
) -> Result<Option<TufTargetEntry>, VsError> {
    match opt {
        Some(jte) => Ok(Some(convert_target_entry(jte)?)),
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

const NO_KEYS: [Option<TufKey>; 4] = [None, None, None, None];

/// Find the byte range of the `"signed":{...}` value in a TUF JSON envelope.
///
/// Returns the slice covering the inner JSON object (from `{` to `}`).
/// The search correctly skips `"signed":` occurrences inside JSON string values.
fn find_signed_value(json: &[u8]) -> Result<&[u8], VsError> {
    let needle = b"\"signed\":";

    // Find the needle at top-level (not inside a string).
    // We track whether we are inside a JSON string value to skip
    // occurrences of "signed": that appear inside string literals.
    let mut pos = None;
    let mut in_str = false;
    let mut esc = false;
    let mut i = 0;
    while i < json.len() {
        let b = json[i];
        if esc {
            // For \uXXXX escapes, skip the 4 hex digits only if they
            // are valid hex characters. Otherwise treat the sequence as
            // regular characters so we don't skip past a closing quote.
            if b == b'u' && i + 5 <= json.len() {
                let hex_valid = json[i + 1..i + 5]
                    .iter()
                    .all(|&h| matches!(h, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F'));
                if hex_valid {
                    i += 5; // skip 'u' + 4 hex digits
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
            esc = false;
            continue;
        }
        if b == b'\\' && in_str {
            esc = true;
            i += 1;
            continue;
        }
        if b == b'"' {
            // Check for needle match BEFORE toggling in_str, because
            // the opening `"` of `"signed":` is part of the needle.
            if !in_str
                && i + needle.len() <= json.len()
                && &json[i..i + needle.len()] == needle.as_slice()
            {
                pos = Some(i);
                break;
            }
            in_str = !in_str;
            i += 1;
            continue;
        }
        i += 1;
    }
    let pos = pos.ok_or(VsError::InvalidInput)?;

    let mut i = pos + needle.len();
    // Skip whitespace
    while i < json.len() && matches!(json[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    if i >= json.len() || json[i] != b'{' {
        return Err(VsError::InvalidInput);
    }

    let obj_start = i;
    let mut depth: u32 = 0;
    let mut in_string = false;
    let mut escape = false;

    while i < json.len() {
        let b = json[i];
        if escape {
            // For \uXXXX escapes, skip the 4 hex digits only if they
            // are valid hex characters.
            if b == b'u' && i + 5 <= json.len() {
                let hex_valid = json[i + 1..i + 5]
                    .iter()
                    .all(|&h| matches!(h, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F'));
                if hex_valid {
                    i += 4; // skip 4 hex digits (loop will add 1 more)
                }
            }
            escape = false;
        } else if b == b'\\' && in_string {
            escape = true;
        } else if b == b'"' {
            in_string = !in_string;
        } else if !in_string {
            if b == b'{' {
                depth += 1;
            } else if b == b'}' {
                depth -= 1;
                if depth == 0 {
                    return Ok(&json[obj_start..=i]);
                }
            }
        }
        i += 1;
    }
    Err(VsError::InvalidInput)
}

fn parse_tuf_root_inner(
    json: &[u8],
) -> Result<(crate::TufRoot, SignedMetadata, [Option<TufSignature>; 4]), VsError> {
    let (parsed, _): (JsonSignedRoot<'_>, _) =
        serde_json_core::from_slice(json).map_err(|_| VsError::InvalidInput)?;

    let root_keys = convert_key_array(&parsed.signed.keys)?;

    let signatures = [
        convert_sig_option(&parsed.signatures.0)?,
        convert_sig_option(&parsed.signatures.1)?,
        convert_sig_option(&parsed.signatures.2)?,
        convert_sig_option(&parsed.signatures.3)?,
    ];

    // Parse per-role delegation keys if present.
    let targets_keys = match &parsed.signed.targets_keys {
        Some(ka) => convert_key_array(ka)?,
        None => NO_KEYS,
    };
    let snapshot_keys = match &parsed.signed.snapshot_keys {
        Some(ka) => convert_key_array(ka)?,
        None => NO_KEYS,
    };
    let timestamp_keys = match &parsed.signed.timestamp_keys {
        Some(ka) => convert_key_array(ka)?,
        None => NO_KEYS,
    };

    let root = crate::TufRoot {
        version: parsed.signed.version,
        expires_us: parsed.signed.expires_us,
        root_keys,
        threshold: parsed.signed.threshold,
        targets_keys,
        targets_threshold: parsed.signed.targets_threshold.unwrap_or(1),
        snapshot_keys,
        snapshot_threshold: parsed.signed.snapshot_threshold.unwrap_or(1),
        timestamp_keys,
        timestamp_threshold: parsed.signed.timestamp_threshold.unwrap_or(1),
    };

    let metadata = SignedMetadata {
        version: parsed.signed.version,
        expires_us: parsed.signed.expires_us,
        signatures,
        content_hash: [0u8; 32],
    };

    Ok((root, metadata, signatures))
}

/// Parse TUF root metadata and compute the `content_hash` via SHA-256.
///
/// This is the recommended entry point. It extracts the `"signed":{...}`
/// portion from the JSON envelope and hashes it with the given
/// [`CryptoProvider`], producing a correct `content_hash` for signature
/// verification.
///
/// # Errors
///
/// Returns [`VsError::InvalidInput`] if parsing fails, or propagates
/// errors from the crypto provider.
pub fn parse_tuf_root_with_hash(
    json: &[u8],
    crypto: &impl CryptoProvider,
) -> Result<(crate::TufRoot, SignedMetadata), VsError> {
    let (root, mut metadata, _) = parse_tuf_root_inner(json)?;
    let signed_bytes = find_signed_value(json)?;
    crypto.sha256(signed_bytes, &mut metadata.content_hash)?;
    Ok((root, metadata))
}

/// Parse signed metadata from canonical JSON bytes.
///
/// Used for non-root TUF roles (targets, snapshot, timestamp).
///
/// # Errors
///
/// Returns [`VsError::InvalidInput`] if the JSON is malformed or hex
/// decoding fails.
pub fn parse_signed_metadata(json: &[u8]) -> Result<SignedMetadata, VsError> {
    let (parsed, _): (JsonSignedMetadata<'_>, _) =
        serde_json_core::from_slice(json).map_err(|_| VsError::InvalidInput)?;

    let signatures = [
        convert_sig_option(&parsed.signatures.0)?,
        convert_sig_option(&parsed.signatures.1)?,
        convert_sig_option(&parsed.signatures.2)?,
        convert_sig_option(&parsed.signatures.3)?,
    ];

    let mut content_hash = [0u8; 32];
    hex_decode(parsed.content_hash, &mut content_hash)?;

    Ok(SignedMetadata {
        version: parsed.version,
        expires_us: parsed.expires_us,
        signatures,
        content_hash,
    })
}

/// Parse TUF timestamp metadata from canonical JSON bytes.
///
/// # Errors
///
/// Returns [`VsError::InvalidInput`] if the JSON is malformed or hex
/// decoding fails.
pub fn parse_tuf_timestamp(json: &[u8]) -> Result<TufTimestamp, VsError> {
    let (parsed, _): (JsonTimestamp<'_>, _) =
        serde_json_core::from_slice(json).map_err(|_| VsError::InvalidInput)?;

    let mut snapshot_hash = [0u8; 32];
    hex_decode(parsed.snapshot_hash, &mut snapshot_hash)?;

    Ok(TufTimestamp {
        version: parsed.version,
        expires_us: parsed.expires_us,
        snapshot_version: parsed.snapshot_version,
        snapshot_hash,
    })
}

/// Parse TUF snapshot metadata from canonical JSON bytes.
///
/// # Errors
///
/// Returns [`VsError::InvalidInput`] if the JSON is malformed or hex
/// decoding fails.
pub fn parse_tuf_snapshot(json: &[u8]) -> Result<TufSnapshot, VsError> {
    let (parsed, _): (JsonSnapshot<'_>, _) =
        serde_json_core::from_slice(json).map_err(|_| VsError::InvalidInput)?;

    let mut targets_hash = [0u8; 32];
    hex_decode(parsed.targets_hash, &mut targets_hash)?;

    Ok(TufSnapshot {
        version: parsed.version,
        expires_us: parsed.expires_us,
        targets_version: parsed.targets_version,
        targets_hash,
    })
}

/// Parse TUF targets metadata from canonical JSON bytes.
///
/// # Errors
///
/// Returns [`VsError::InvalidInput`] if the JSON is malformed or hex
/// decoding fails.
pub fn parse_tuf_targets(json: &[u8]) -> Result<TufTargets, VsError> {
    let (parsed, _): (JsonTargetsSigned<'_>, _) =
        serde_json_core::from_slice(json).map_err(|_| VsError::InvalidInput)?;

    let targets = [
        convert_target_entry_option(&parsed.targets.0)?,
        convert_target_entry_option(&parsed.targets.1)?,
        convert_target_entry_option(&parsed.targets.2)?,
        convert_target_entry_option(&parsed.targets.3)?,
        convert_target_entry_option(&parsed.targets.4)?,
        convert_target_entry_option(&parsed.targets.5)?,
        convert_target_entry_option(&parsed.targets.6)?,
        convert_target_entry_option(&parsed.targets.7)?,
    ];

    Ok(TufTargets {
        version: parsed.version,
        expires_us: parsed.expires_us,
        targets,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::format;
    use vs_crypto::KeyId;

    // Minimal shared crypto mock — only `sha256` does real work; everything
    // else returns `NotInitialized`. Lifted to module scope so multiple
    // tests can share it.
    struct HashCrypto;
    impl vs_crypto::CryptoProvider for HashCrypto {
        fn aes_gcm_encrypt(
            &self,
            _: KeyId,
            _: &[u8; 12],
            _: &[u8],
            _: &[u8],
            _: &mut [u8],
            _: &mut [u8; 16],
        ) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }
        fn aes_gcm_decrypt(
            &self,
            _: KeyId,
            _: &[u8; 12],
            _: &[u8],
            _: &[u8],
            _: &[u8; 16],
            _: &mut [u8],
        ) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }
        fn sha256(&self, data: &[u8], hash_out: &mut [u8; 32]) -> Result<(), VsError> {
            *hash_out = [0u8; 32];
            for (i, &b) in data.iter().enumerate() {
                hash_out[i % 32] ^= b;
            }
            Ok(())
        }
        fn hmac_sha256(&self, _: KeyId, _: &[u8], _: &mut [u8; 32]) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }
        fn ecdh_derive_shared(
            &self,
            _: KeyId,
            _: &[u8; 65],
            _: &mut [u8; 32],
        ) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }
        fn sign_p256(&self, _: KeyId, _: &[u8; 32], _: &mut [u8; 64]) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }
        fn verify_p256(&self, _: &[u8; 65], _: &[u8; 32], _: &[u8; 64]) -> Result<bool, VsError> {
            Ok(false)
        }
        fn random_bytes(&self, _: &mut [u8]) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }
        fn delete_key(&mut self, _: KeyId) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }
        fn generate_key(&mut self, _: KeyId, _: vs_crypto::KeyType) -> Result<(), VsError> {
            Err(VsError::NotInitialized)
        }
    }

    #[test]
    fn hex_decode_valid() {
        let mut out = [0u8; 4];
        hex_decode("deadbeef", &mut out).unwrap();
        assert_eq!(out, [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn hex_decode_uppercase() {
        let mut out = [0u8; 2];
        hex_decode("AB0F", &mut out).unwrap();
        assert_eq!(out, [0xAB, 0x0F]);
    }

    #[test]
    fn hex_decode_wrong_length() {
        let mut out = [0u8; 4];
        assert!(hex_decode("aabb", &mut out).is_err()); // too short
        assert!(hex_decode("aabbccddeeff", &mut out).is_err()); // too long
    }

    #[test]
    fn hex_decode_invalid_char() {
        let mut out = [0u8; 2];
        assert!(hex_decode("zz00", &mut out).is_err());
    }

    #[test]
    fn parse_tuf_root_with_hash_minimal() {
        let key_id_hex = "aa".repeat(32);
        let pubkey_hex = "bb".repeat(65);
        let sig_hex = "cc".repeat(64);

        let json = format!(
            r#"{{"signatures":[{{"keyid":"{key_id_hex}","sig":"{sig_hex}"}},null,null,null],"signed":{{"version":1,"expires_us":1000000,"threshold":1,"keys":[{{"keyid":"{key_id_hex}","keytype":"ecdsa-sha2-nistp256","keyval":{{"public":"{pubkey_hex}"}}}},null,null,null]}}}}"#,
        );

        let (root, metadata) = parse_tuf_root_with_hash(json.as_bytes(), &HashCrypto).unwrap();

        assert_eq!(root.version, 1);
        assert_eq!(root.expires_us, 1_000_000);
        assert_eq!(root.threshold, 1);
        assert!(root.root_keys[0].is_some());
        assert!(root.root_keys[1].is_none());

        let key = root.root_keys[0].as_ref().unwrap();
        assert_eq!(key.key_id, [0xAA; 32]);
        assert_eq!(key.key_type, KeyType::EcdsaP256);
        assert_eq!(key.public_key, [0xBB; 65]);

        assert_eq!(metadata.version, 1);
        assert!(metadata.signatures[0].is_some());
        let sig = metadata.signatures[0].as_ref().unwrap();
        assert_eq!(sig.key_id, [0xAA; 32]);
        assert_eq!(sig.sig, [0xCC; 64]);

        // Per-role keys should be empty when not specified.
        assert!(root.targets_keys.iter().all(|k| k.is_none()));
        assert_eq!(root.targets_threshold, 0);
    }

    #[test]
    fn parse_tuf_root_with_hash_multiple_keys_and_sigs() {
        let k1_id = "01".repeat(32);
        let k2_id = "02".repeat(32);
        let pubkey1 = "a1".repeat(65);
        let pubkey2 = "a2".repeat(65);
        let sig1 = "b1".repeat(64);
        let sig2 = "b2".repeat(64);

        let json = format!(
            r#"{{"signatures":[{{"keyid":"{k1_id}","sig":"{sig1}"}},{{"keyid":"{k2_id}","sig":"{sig2}"}},null,null],"signed":{{"version":3,"expires_us":5000000,"threshold":2,"keys":[{{"keyid":"{k1_id}","keytype":"ecdsa-sha2-nistp256","keyval":{{"public":"{pubkey1}"}}}},{{"keyid":"{k2_id}","keytype":"ecdsa-sha2-nistp256","keyval":{{"public":"{pubkey2}"}}}},null,null]}}}}"#,
        );

        let (root, metadata) = parse_tuf_root_with_hash(json.as_bytes(), &HashCrypto).unwrap();

        assert_eq!(root.version, 3);
        assert_eq!(root.threshold, 2);
        assert!(root.root_keys[0].is_some());
        assert!(root.root_keys[1].is_some());
        assert!(root.root_keys[2].is_none());

        assert!(metadata.signatures[0].is_some());
        assert!(metadata.signatures[1].is_some());
        assert!(metadata.signatures[2].is_none());
    }

    #[test]
    fn parse_tuf_root_with_hash_invalid_json() {
        let result = parse_tuf_root_with_hash(b"not json at all", &HashCrypto);
        assert!(result.is_err());
    }

    #[test]
    fn parse_tuf_root_with_hash_bad_hex_key_id() {
        let bad_hex = "zz".repeat(32);
        let pubkey_hex = "bb".repeat(65);
        let sig_hex = "cc".repeat(64);

        let json = format!(
            r#"{{"signatures":[{{"keyid":"{bad_hex}","sig":"{sig_hex}"}},null,null,null],"signed":{{"version":1,"expires_us":1000000,"threshold":1,"keys":[{{"keyid":"{bad_hex}","keytype":"ecdsa-sha2-nistp256","keyval":{{"public":"{pubkey_hex}"}}}},null,null,null]}}}}"#,
        );

        let result = parse_tuf_root_with_hash(json.as_bytes(), &HashCrypto);
        assert!(result.is_err());
    }

    #[test]
    fn parse_tuf_root_rejects_legacy_key_type_aliases() {
        // Pre-0.7.0 the parser accepted "ecdsa" and "EcdsaP256" as aliases
        // for "ecdsa-sha2-nistp256". Both must now be rejected.
        let key_id_hex = "aa".repeat(32);
        let pubkey_hex = "bb".repeat(65);
        let sig_hex = "cc".repeat(64);
        for alias in ["ecdsa", "EcdsaP256"] {
            let json = format!(
                r#"{{"signatures":[{{"keyid":"{key_id_hex}","sig":"{sig_hex}"}},null,null,null],"signed":{{"version":1,"expires_us":1000000,"threshold":1,"keys":[{{"keyid":"{key_id_hex}","keytype":"{alias}","keyval":{{"public":"{pubkey_hex}"}}}},null,null,null]}}}}"#,
            );
            let result = parse_tuf_root_with_hash(json.as_bytes(), &HashCrypto);
            assert!(result.is_err(), "legacy alias {alias:?} must be rejected");
        }
    }

    #[test]
    fn parse_signed_metadata_valid() {
        let k_id = "dd".repeat(32);
        let sig_hex = "ee".repeat(64);
        let hash_hex = "ff".repeat(32);

        let json = format!(
            r#"{{"signatures":[{{"keyid":"{k_id}","sig":"{sig_hex}"}},null,null,null],"version":7,"expires_us":9000000,"content_hash":"{hash_hex}"}}"#,
        );

        let metadata = parse_signed_metadata(json.as_bytes()).unwrap();
        assert_eq!(metadata.version, 7);
        assert_eq!(metadata.expires_us, 9_000_000);
        assert_eq!(metadata.content_hash, [0xFF; 32]);
        assert!(metadata.signatures[0].is_some());
        let sig = metadata.signatures[0].as_ref().unwrap();
        assert_eq!(sig.key_id, [0xDD; 32]);
        assert_eq!(sig.sig, [0xEE; 64]);
    }

    #[test]
    fn parse_signed_metadata_invalid_content_hash() {
        let k_id = "dd".repeat(32);
        let sig_hex = "ee".repeat(64);

        let json = format!(
            r#"{{"signatures":[{{"keyid":"{k_id}","sig":"{sig_hex}"}},null,null,null],"version":1,"expires_us":1000000,"content_hash":"tooshort"}}"#,
        );

        let result = parse_signed_metadata(json.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn find_signed_value_extracts_inner_object() {
        let json = br#"{"signatures":[],"signed":{"version":1,"expires_us":1000}}"#;
        let signed = find_signed_value(json).unwrap();
        assert_eq!(signed, br#"{"version":1,"expires_us":1000}"#);
    }

    #[test]
    fn find_signed_value_missing() {
        let json = br#"{"signatures":[]}"#;
        assert!(find_signed_value(json).is_err());
    }

    #[test]
    fn find_signed_value_skips_string_embedded_needle() {
        // The string value contains "signed":{...} but the parser should skip it
        // and find the real top-level "signed" field.
        let json =
            br#"{"debug":"\"signed\":{\"fake\":true}","signatures":[],"signed":{"version":2,"expires_us":2000}}"#;
        let signed = find_signed_value(json).unwrap();
        assert_eq!(signed, br#"{"version":2,"expires_us":2000}"#);
    }

    #[test]
    fn parse_tuf_root_with_hash_computes_content_hash() {
        let key_id_hex = "aa".repeat(32);
        let pubkey_hex = "bb".repeat(65);
        let sig_hex = "cc".repeat(64);

        let json = format!(
            r#"{{"signatures":[{{"keyid":"{key_id_hex}","sig":"{sig_hex}"}},null,null,null],"signed":{{"version":1,"expires_us":1000000,"threshold":1,"keys":[{{"keyid":"{key_id_hex}","keytype":"ecdsa-sha2-nistp256","keyval":{{"public":"{pubkey_hex}"}}}},null,null,null]}}}}"#,
        );

        // `parse_tuf_root_with_hash` hashes the `"signed":{...}` envelope so
        // `content_hash` is non-zero (and matches the SHA-256 of the slice).
        let (_, metadata_with_hash) =
            parse_tuf_root_with_hash(json.as_bytes(), &HashCrypto).unwrap();
        assert_ne!(metadata_with_hash.content_hash, [0u8; 32]);
    }

    #[test]
    fn parse_tuf_root_unsupported_keytype() {
        let key_id_hex = "aa".repeat(32);
        let pubkey_hex = "bb".repeat(65);
        let sig_hex = "cc".repeat(64);

        let json = format!(
            r#"{{"signatures":[{{"keyid":"{key_id_hex}","sig":"{sig_hex}"}},null,null,null],"signed":{{"version":1,"expires_us":1000000,"threshold":1,"keys":[{{"keyid":"{key_id_hex}","keytype":"rsa","keyval":{{"public":"{pubkey_hex}"}}}},null,null,null]}}}}"#,
        );

        let result = parse_tuf_root_with_hash(json.as_bytes(), &HashCrypto);
        assert!(result.is_err());
    }

    #[test]
    fn parse_tuf_root_with_per_role_keys() {
        let root_key_id = "01".repeat(32);
        let root_pubkey = "a1".repeat(65);
        let targets_key_id = "02".repeat(32);
        let targets_pubkey = "a2".repeat(65);
        let sig_hex = "cc".repeat(64);

        let json = format!(
            r#"{{"signatures":[{{"keyid":"{root_key_id}","sig":"{sig_hex}"}},null,null,null],"signed":{{"version":1,"expires_us":1000000,"threshold":1,"keys":[{{"keyid":"{root_key_id}","keytype":"ecdsa-sha2-nistp256","keyval":{{"public":"{root_pubkey}"}}}},null,null,null],"targets_keys":[{{"keyid":"{targets_key_id}","keytype":"ecdsa-sha2-nistp256","keyval":{{"public":"{targets_pubkey}"}}}},null,null,null],"targets_threshold":2}}}}"#,
        );

        let (root, _) = parse_tuf_root_with_hash(json.as_bytes(), &HashCrypto).unwrap();
        assert!(root.targets_keys[0].is_some());
        assert_eq!(root.targets_threshold, 2);
        let tk = root.targets_keys[0].as_ref().unwrap();
        assert_eq!(tk.key_id, [0x02; 32]);

        // Other role keys should still be empty.
        assert!(root.snapshot_keys.iter().all(|k| k.is_none()));
        assert_eq!(root.snapshot_threshold, 0);
    }

    // -- Delegation metadata parsing tests --------------------------------

    #[test]
    fn parse_tuf_timestamp_valid() {
        let hash_hex = "ab".repeat(32);
        let json = format!(
            r#"{{"version":5,"expires_us":9000000,"snapshot_version":3,"snapshot_hash":"{hash_hex}"}}"#,
        );
        let ts = parse_tuf_timestamp(json.as_bytes()).unwrap();
        assert_eq!(ts.version, 5);
        assert_eq!(ts.expires_us, 9_000_000);
        assert_eq!(ts.snapshot_version, 3);
        assert_eq!(ts.snapshot_hash, [0xAB; 32]);
    }

    #[test]
    fn parse_tuf_timestamp_invalid() {
        assert!(parse_tuf_timestamp(b"not json").is_err());
    }

    #[test]
    fn parse_tuf_snapshot_valid() {
        let hash_hex = "cd".repeat(32);
        let json = format!(
            r#"{{"version":2,"expires_us":8000000,"targets_version":7,"targets_hash":"{hash_hex}"}}"#,
        );
        let snap = parse_tuf_snapshot(json.as_bytes()).unwrap();
        assert_eq!(snap.version, 2);
        assert_eq!(snap.expires_us, 8_000_000);
        assert_eq!(snap.targets_version, 7);
        assert_eq!(snap.targets_hash, [0xCD; 32]);
    }

    #[test]
    fn parse_tuf_snapshot_invalid() {
        assert!(parse_tuf_snapshot(b"{}").is_err());
    }

    #[test]
    fn parse_tuf_targets_valid() {
        let hash_hex = "ef".repeat(32);
        let json = format!(
            r#"{{"version":1,"expires_us":5000000,"targets":[{{"hash":"{hash_hex}","length":1024,"target_id":"ecu-main"}},null,null,null,null,null,null,null]}}"#,
        );
        let targets = parse_tuf_targets(json.as_bytes()).unwrap();
        assert_eq!(targets.version, 1);
        assert_eq!(targets.expires_us, 5_000_000);
        assert!(targets.targets[0].is_some());
        let entry = targets.targets[0].as_ref().unwrap();
        assert_eq!(entry.hash, [0xEF; 32]);
        assert_eq!(entry.length, 1024);
        assert_eq!(&entry.target_id[..8], b"ecu-main");
        assert_eq!(entry.target_id_len, 8);
        assert!(targets.targets[1].is_none());
    }

    #[test]
    fn parse_tuf_targets_empty() {
        let json = br#"{"version":1,"expires_us":5000000,"targets":[null,null,null,null,null,null,null,null]}"#;
        let targets = parse_tuf_targets(json).unwrap();
        assert!(targets.targets.iter().all(|t| t.is_none()));
    }

    #[test]
    fn parse_tuf_targets_invalid() {
        assert!(parse_tuf_targets(b"not json").is_err());
    }

    #[test]
    fn parse_tuf_targets_bad_hash() {
        let json = br#"{"version":1,"expires_us":5000000,"targets":[{"hash":"tooshort","length":10,"target_id":"x"},null,null,null,null,null,null,null]}"#;
        assert!(parse_tuf_targets(json).is_err());
    }
}
