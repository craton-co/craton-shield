// SPDX-License-Identifier: Apache-2.0
#![no_main]
use libfuzzer_sys::fuzz_target;
use vs_crypto::SoftwareCryptoProvider;
use vs_ota_validator::json;

fuzz_target!(|data: &[u8]| {
    // Feed arbitrary bytes to all OTA JSON parsers.
    // None of these must panic on any input.
    let crypto = SoftwareCryptoProvider::default();

    // Try parsing as signed root (with content hash computation)
    let _ = json::parse_tuf_root_with_hash(data, &crypto);

    // Try parsing as signed metadata (non-root roles)
    let _ = json::parse_signed_metadata(data);

    // Try parsing as TUF timestamp metadata
    let _ = json::parse_tuf_timestamp(data);

    // Try parsing as TUF snapshot metadata
    let _ = json::parse_tuf_snapshot(data);

    // Try parsing as TUF targets metadata
    let _ = json::parse_tuf_targets(data);
});
