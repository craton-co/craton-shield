// SPDX-License-Identifier: Apache-2.0
//! ABI regression tests for the `vs-ffi` C ABI.
//!
//! These tests pin the **byte-level** layout of every `#[repr(C)]` struct
//! exposed across the FFI boundary, plus the `VS_ABI_VERSION` constant and
//! its `vs_abi_version()` query function.
//!
//! If any of these tests fail, the C ABI has changed and one of the
//! following must happen, *in the same commit*:
//!
//! 1. The change is intentional and bumps the major component of
//!    `VS_ABI_VERSION`.  Update both `cratonshield.h` and
//!    `core/ffi/src/lib.rs`, then update the assertions below.
//! 2. The change is intentional and qualifies as a backward-compatible
//!    addition (see `ABI.md`).  Update `VS_ABI_VERSION` accordingly and
//!    extend (do not modify) the assertions below.
//! 3. The change is accidental — revert it.
//!
//! See `ABI.md` at the workspace root for the full versioning policy.

use core::mem::{align_of, offset_of, size_of};

use vs_ffi::{vs_abi_version, VsCanFrame, VsHealth, VsResult, VS_ABI_VERSION};

// ---------------------------------------------------------------------------
// VS_ABI_VERSION
// ---------------------------------------------------------------------------

#[test]
fn abi_version_constant_matches_header() {
    // The Rust constant MUST match the value documented in
    // `core/include/cratonshield.h` (`#define VS_ABI_VERSION 0x00010000`).
    // The C header has a matching `_Static_assert` on the size of every
    // struct below; this test is the Rust-side counterpart.
    assert_eq!(VS_ABI_VERSION, 0x0001_0000);
}

#[test]
fn abi_version_query_returns_constant() {
    // The exported `vs_abi_version()` function MUST return `VS_ABI_VERSION`.
    // Downstream C consumers call this at init to detect a header/library
    // skew.
    assert_eq!(vs_abi_version(), VS_ABI_VERSION);
}

#[test]
fn abi_version_major_is_one() {
    // Bumping the major component is a deliberate breaking change.  Spell
    // out the current major version explicitly so an accidental bump shows
    // up as a test diff.
    let major = (VS_ABI_VERSION >> 16) & 0xFFFF;
    assert_eq!(major, 1, "VS_ABI_VERSION major component must be 1");
}

// ---------------------------------------------------------------------------
// VsResult
// ---------------------------------------------------------------------------

#[test]
fn vs_result_size_and_align() {
    assert_eq!(size_of::<VsResult>(), 4, "VsResult must be exactly 4 bytes");
    assert_eq!(align_of::<VsResult>(), 4, "VsResult must be 4-byte aligned");
}

#[test]
fn vs_result_field_offsets() {
    assert_eq!(offset_of!(VsResult, code), 0);
}

// ---------------------------------------------------------------------------
// VsCanFrame
// ---------------------------------------------------------------------------

#[test]
fn vs_can_frame_size_and_align() {
    // Pinned at 80 bytes — also asserted by `_Static_assert` in
    // `core/include/cratonshield.h` and by a `const _: ()` block in
    // `core/ffi/src/lib.rs`.
    assert_eq!(
        size_of::<VsCanFrame>(),
        80,
        "VsCanFrame must be exactly 80 bytes"
    );
    // The struct is aligned to its largest field, the `u64 timestamp_us`.
    assert_eq!(
        align_of::<VsCanFrame>(),
        8,
        "VsCanFrame must be 8-byte aligned"
    );
}

#[test]
fn vs_can_frame_field_offsets() {
    // Layout (Itanium / SysV C ABI; #[repr(C)] guarantees this everywhere
    // craton-shield is supported):
    //   id          u32   @ 0
    //   dlc         u8    @ 4
    //   data        [u8;64] @ 5
    //   is_extended u8    @ 69
    //   is_fd       u8    @ 70
    //   _padding (compiler-inserted): 1 byte @ 71
    //   timestamp_us u64  @ 72
    //   end of struct                @ 80
    assert_eq!(offset_of!(VsCanFrame, id), 0);
    assert_eq!(offset_of!(VsCanFrame, dlc), 4);
    assert_eq!(offset_of!(VsCanFrame, data), 5);
    assert_eq!(offset_of!(VsCanFrame, is_extended), 69);
    assert_eq!(offset_of!(VsCanFrame, is_fd), 70);
    assert_eq!(offset_of!(VsCanFrame, timestamp_us), 72);
}

// ---------------------------------------------------------------------------
// VsHealth
// ---------------------------------------------------------------------------

#[test]
fn vs_health_size_and_align() {
    // 14 i32 fields × 4 bytes = 56 bytes, also asserted in cratonshield.h.
    assert_eq!(
        size_of::<VsHealth>(),
        56,
        "VsHealth must be exactly 56 bytes"
    );
    assert_eq!(align_of::<VsHealth>(), 4);
}

#[test]
fn vs_health_field_offsets() {
    // Order of fields is part of the ABI — reorder = major bump.
    assert_eq!(offset_of!(VsHealth, crypto), 0);
    assert_eq!(offset_of!(VsHealth, key_manager), 4);
    assert_eq!(offset_of!(VsHealth, secure_boot), 8);
    assert_eq!(offset_of!(VsHealth, event_logger), 12);
    assert_eq!(offset_of!(VsHealth, can_monitor), 16);
    assert_eq!(offset_of!(VsHealth, eth_monitor), 20);
    assert_eq!(offset_of!(VsHealth, ids_engine), 24);
    assert_eq!(offset_of!(VsHealth, firewall), 28);
    assert_eq!(offset_of!(VsHealth, ota_validator), 32);
    assert_eq!(offset_of!(VsHealth, anomaly), 36);
    assert_eq!(offset_of!(VsHealth, integrity), 40);
    assert_eq!(offset_of!(VsHealth, policy_engine), 44);
    assert_eq!(offset_of!(VsHealth, storage), 48);
    assert_eq!(offset_of!(VsHealth, hal), 52);
}

// ---------------------------------------------------------------------------
// Error code stability
// ---------------------------------------------------------------------------

#[test]
fn error_codes_are_stable() {
    // The numeric values of every error code are part of the ABI.  Changing
    // any of these = major bump.
    use vs_ffi::{
        VS_ERR_ALREADY_INITIALIZED, VS_ERR_AUTH_FAILURE, VS_ERR_CRYPTO, VS_ERR_INTERNAL,
        VS_ERR_INVALID_ARG, VS_ERR_KEY_EXPIRED, VS_ERR_KEY_REVOKED, VS_ERR_NOT_FOUND,
        VS_ERR_NOT_INITIALIZED, VS_ERR_POLICY_VIOLATION, VS_ERR_RATE_LIMITED,
        VS_ERR_RESOURCE_EXHAUSTED, VS_ERR_STATE_CORRUPTED, VS_ERR_TIMEOUT, VS_OK,
    };
    assert_eq!(VS_OK, 0);
    assert_eq!(VS_ERR_INVALID_ARG, -1);
    assert_eq!(VS_ERR_NOT_INITIALIZED, -2);
    assert_eq!(VS_ERR_INTERNAL, -3);
    assert_eq!(VS_ERR_RATE_LIMITED, -4);
    assert_eq!(VS_ERR_ALREADY_INITIALIZED, -5);
    assert_eq!(VS_ERR_CRYPTO, -6);
    assert_eq!(VS_ERR_RESOURCE_EXHAUSTED, -7);
    assert_eq!(VS_ERR_POLICY_VIOLATION, -8);
    assert_eq!(VS_ERR_AUTH_FAILURE, -9);
    assert_eq!(VS_ERR_TIMEOUT, -10);
    assert_eq!(VS_ERR_NOT_FOUND, -11);
    assert_eq!(VS_ERR_KEY_EXPIRED, -12);
    assert_eq!(VS_ERR_KEY_REVOKED, -13);
    assert_eq!(VS_ERR_STATE_CORRUPTED, -14);
}

// ---------------------------------------------------------------------------
// VsCryptoCallbacks self-consistency
//
// `VsCryptoCallbacks` lives in the sibling `vs-ffi-auto` crate.  The
// equivalent self-consistency assertions for that struct (size, magic
// canary, field offsets) live in that crate's own ABI test suite — see
// `auto/ffi-auto/tests/abi.rs`.  Keeping the assertions next to the
// struct definition keeps the test failure message actionable.
// ---------------------------------------------------------------------------
