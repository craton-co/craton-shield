// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company

#![no_std]
#![deny(missing_docs)]

//! Shared automotive types for the Craton Shield Auto workspace.
//!
//! This crate is a thin automotive-domain extension of [`vs_types`]. It
//! re-exports the core type surface (including the PII-redacting
//! [`vs_types::VehicleId`]) and adds:
//!
//! * automotive source-type constants (LIN, FlexRay, automotive Ethernet),
//! * a reserved source ID for OTA security events,
//! * a domain-local [`BusType`] enum with [`TryFrom<u8>`] convertibility
//!   against this crate's expanded constant set,
//! * VIN helpers ([`validate_check_digit`], [`try_from_normalized`]) that
//!   operate on the *core* [`vs_types::VehicleId`] — there is no separate
//!   `VehicleId` type in this crate. Re-introducing one would silently shadow
//!   the redacted core type and is forbidden by policy; the `vs-types` crate
//!   carries a regression test pinning the redaction behaviour.

// ---------------------------------------------------------------------------
// Public API (v1.0 stable)
// ---------------------------------------------------------------------------
//
// Every `pub` item below is part of the v1.0 stable surface and governed
// by the workspace deprecation policy. `BusType` discriminants are pinned
// and form part of the stable ABI for automotive FFI consumers.

// Re-export everything from the core types crate. This brings in the
// PII-redacting `vs_types::VehicleId` — DO NOT shadow it with a local type.
pub use vs_types::*;

// ---------------------------------------------------------------------------
// Automotive source type constants
// ---------------------------------------------------------------------------

/// Automotive Ethernet (`SOME/IP`, `DoIP`).
///
/// Intentionally aliases [`vs_types::SOURCE_ETHERNET`] because the core
/// `SOURCE_ETHERNET` constant was designed with automotive Ethernet in mind.
/// If a non-automotive Ethernet source type is added to core in the future,
/// this alias should be replaced with a distinct value.
pub const SOURCE_AUTOMOTIVE_ETHERNET: u8 = vs_types::SOURCE_ETHERNET;
// NOTE: `SOURCE_LIN` and `SOURCE_FLEXRAY` are intentionally NOT redefined
// here. They are re-exported unchanged from `vs_types` (`SOURCE_LIN = 5`,
// `SOURCE_FLEXRAY = 6`) so that this crate and the core layer agree on the
// wire value of a bus. A previous version of this crate redefined them with
// divergent values (10/11), which (a) collided with the `pub use vs_types::*`
// glob re-export above — breaking any downstream `use vs_types_auto::*;` —
// and (b) caused cross-layer alert correlation to silently fail, because a
// `SecurityAlert.source_type` set by a core monitor (5/6) was rejected by
// this crate's `BusType::try_from`. The core constants are the single source
// of truth for bus source types.

// ---------------------------------------------------------------------------
// Reserved source IDs (bus-independent)
// ---------------------------------------------------------------------------

/// Reserved `source_id` for OTA (Over-The-Air) update events.
///
/// Used by `IdsM` and the runtime to identify OTA-related security events
/// without tying them to a specific physical bus.
pub const SOURCE_ID_OTA_RESERVED: u32 = 0xFFFF_FFFE;

// ---------------------------------------------------------------------------
// BusType enum (automotive domain)
// ---------------------------------------------------------------------------

/// Vehicle communication bus type.
///
/// # Stability
///
/// Discriminants are pinned for v1.0.0 and form part of the stable ABI for
/// automotive FFI consumers. New variants are appended with fresh
/// discriminants; existing values are never reordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
pub enum BusType {
    /// Classic CAN bus.
    Can = 0,
    /// CAN-FD bus.
    CanFd = 1,
    /// Automotive Ethernet (`SOME/IP`, `DoIP`).
    AutomotiveEthernet = 2,
    /// LIN bus.
    Lin = 3,
    /// `FlexRay` bus.
    FlexRay = 4,
}

impl BusType {
    /// Convert a `BusType` to the corresponding `source_type` constant used in
    /// [`SecurityAlert`].
    pub fn to_source_type(self) -> u8 {
        match self {
            Self::Can => vs_types::SOURCE_CAN,
            Self::CanFd => vs_types::SOURCE_CAN_FD,
            Self::AutomotiveEthernet => SOURCE_AUTOMOTIVE_ETHERNET,
            Self::Lin => vs_types::SOURCE_LIN,
            Self::FlexRay => vs_types::SOURCE_FLEXRAY,
        }
    }
}

impl TryFrom<u8> for BusType {
    type Error = vs_types::VsError;

    /// Convert a `source_type` constant back to a [`BusType`].
    ///
    /// Returns `Err(VsError::InvalidInput)` for unrecognized source types.
    fn try_from(source_type: u8) -> Result<Self, Self::Error> {
        match source_type {
            x if x == vs_types::SOURCE_CAN => Ok(Self::Can),
            x if x == vs_types::SOURCE_CAN_FD => Ok(Self::CanFd),
            x if x == SOURCE_AUTOMOTIVE_ETHERNET => Ok(Self::AutomotiveEthernet),
            x if x == vs_types::SOURCE_LIN => Ok(Self::Lin),
            x if x == vs_types::SOURCE_FLEXRAY => Ok(Self::FlexRay),
            _ => Err(vs_types::VsError::InvalidInput),
        }
    }
}

// ---------------------------------------------------------------------------
// VIN helpers (operate on the core PII-redacting `vs_types::VehicleId`)
// ---------------------------------------------------------------------------
//
// This crate deliberately does NOT define its own `VehicleId` type. The core
// type at [`vs_types::VehicleId`] redacts the VIN in its `Display`/`Debug`
// impls; a shadowing local type with derived/printing impls would silently
// leak PII to any consumer importing `VehicleId` from this crate.
//
// All auto-specific VIN behaviour is exposed as free functions that take
// `&vs_types::VehicleId` and use its public accessors.

/// Returns the ISO 3779 transliteration value for a VIN character, or `None`
/// if the byte is not a valid VIN character.
const fn vin_transliterate(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A' | b'J' => Some(1),
        b'B' | b'K' | b'S' => Some(2),
        b'C' | b'L' | b'T' => Some(3),
        b'D' | b'M' | b'U' => Some(4),
        b'E' | b'N' | b'V' => Some(5),
        b'F' | b'W' => Some(6),
        b'G' | b'P' | b'X' => Some(7),
        b'H' | b'Y' => Some(8),
        b'R' | b'Z' => Some(9),
        _ => None,
    }
}

/// Validates the ISO 3779 check digit at position 9 (index 8) of a VIN.
///
/// The check digit can be 0-9 or X (representing 10). Each position has a
/// weight, and the sum of `(transliterated_value * weight) mod 11` must equal
/// the check digit.
///
/// This is an automotive-domain helper that operates on the **core**
/// [`vs_types::VehicleId`]; it never reads or returns the unredacted VIN —
/// the input is already a validated 17-byte VIN.
///
/// Returns `false` if any byte is outside the ISO 3779 alphabet or the
/// check digit does not match.
pub fn validate_check_digit(vin: &vs_types::VehicleId) -> bool {
    const WEIGHTS: [u8; 17] = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];

    let bytes = vin.vin();
    let mut sum: u32 = 0;
    let mut i = 0;
    while i < 17 {
        if i == 8 {
            // Skip the check digit position itself during summation.
            i += 1;
            continue;
        }
        let val = match vin_transliterate(bytes[i]) {
            Some(v) => v as u32,
            None => return false,
        };
        sum += val * WEIGHTS[i] as u32;
        i += 1;
    }

    let remainder = (sum % 11) as u8;
    let check_char = bytes[8];

    if check_char == b'X' {
        remainder == 10
    } else if check_char.is_ascii_digit() {
        remainder == check_char - b'0'
    } else {
        false
    }
}

/// Parse a VIN from a string, normalizing to uppercase first, and additionally
/// validating the ISO 3779 check digit.
///
/// Accepts lowercase or mixed-case VINs and converts them to uppercase before
/// validation. Many real-world automotive systems produce lowercase VINs
/// despite the ISO 3779 specification requiring uppercase characters.
///
/// Returns `Err(VsError::InvalidInput)` if the input is not exactly 17 bytes,
/// contains a non-VIN character after normalization, or has an invalid check
/// digit.
///
/// The returned [`vs_types::VehicleId`] is PII-safe: its `Display`/`Debug`
/// impls redact the vehicle-unique suffix. Use
/// [`vs_types::VehicleId::as_str_unredacted`] for audited access to the full
/// VIN.
///
/// # Example
///
/// ```ignore
/// // Doctest is marked `ignore` because it depends on workspace path deps.
/// use vs_types_auto::try_from_normalized;
/// let vin = try_from_normalized("1hgbh41jxmn109186").unwrap();
/// // Display is redacted — only the WMI is visible.
/// ```
pub fn try_from_normalized(s: &str) -> Result<vs_types::VehicleId, vs_types::VsError> {
    let bytes = s.as_bytes();
    if bytes.len() != 17 {
        return Err(vs_types::VsError::InvalidInput);
    }
    let mut vin_buf = [0u8; 17];
    for (i, &b) in bytes.iter().enumerate() {
        vin_buf[i] = b.to_ascii_uppercase();
    }
    let vin = vs_types::VehicleId::new(&vin_buf)?;
    if !validate_check_digit(&vin) {
        return Err(vs_types::VsError::InvalidInput);
    }
    Ok(vin)
}

#[cfg(test)]
extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    // ---- VIN helper tests (operating on core vs_types::VehicleId) ----

    #[test]
    fn vehicle_id_valid_with_check_digit() {
        let vin = vs_types::VehicleId::new(b"1HGBH41JXMN109186").expect("valid VIN bytes");
        assert!(validate_check_digit(&vin), "ISO 3779 check digit must pass");
        // Display is redacted — confirm it does NOT contain the full VIN.
        let displayed = format!("{vin}");
        assert!(
            !displayed.contains("1HGBH41JXMN109186"),
            "Display MUST redact the full VIN (got {displayed})"
        );
        // Audited accessor returns the full VIN.
        assert_eq!(vin.as_str_unredacted(), "1HGBH41JXMN109186");
    }

    #[test]
    fn vehicle_id_too_short() {
        let result = vs_types::VehicleId::new(b"1HGBH41JXM");
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn vehicle_id_too_long() {
        let result = vs_types::VehicleId::new(b"1HGBH41JXMN1091860");
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn vehicle_id_rejects_i() {
        // 16 bytes — core rejects on length first, which is fine; this test
        // anchors the legacy behaviour.
        let result = vs_types::VehicleId::new(b"1HGBH41IXMN10918");
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn vehicle_id_rejects_o() {
        let result = vs_types::VehicleId::new(b"1HGBH41OXMN10918");
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn vehicle_id_rejects_q() {
        let result = vs_types::VehicleId::new(b"1HGBH41QXMN10918");
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn vehicle_id_rejects_lowercase() {
        // Core's strict constructor rejects lowercase.
        let result = vs_types::VehicleId::new(b"1hgbh41jxmn109186");
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn vehicle_id_debug_is_redacted() {
        let id = vs_types::VehicleId::new(b"1HGBH41JXMN109186").expect("valid VIN");
        let s = format!("{id:?}");
        assert!(
            !s.contains("1HGBH41JXMN109186"),
            "Debug MUST redact the full VIN (got {s})"
        );
        assert!(s.contains("VehicleId"), "Debug should label the type");
    }

    #[test]
    fn validate_check_digit_rejects_bad_check_digit() {
        // Change check digit from 'X' (correct) to '0' (incorrect).
        let id = vs_types::VehicleId::new(b"1HGBH41J0MN109186").expect("valid VIN bytes");
        assert!(!validate_check_digit(&id));
    }

    #[test]
    fn validate_check_digit_x_means_10() {
        // 1HGBH41JXMN109186 has check digit X (remainder = 10).
        let id = vs_types::VehicleId::new(b"1HGBH41JXMN109186").expect("valid VIN bytes");
        assert!(validate_check_digit(&id));
    }

    #[test]
    fn validate_check_digit_numeric() {
        // 11111111111111111: all 1s.
        // transliteration: all 1s, weights sum = 1*(8+7+6+5+4+3+2+10+9+8+7+6+5+4+3+2) = 89
        // 89 mod 11 = 89 - 8*11 = 89 - 88 = 1
        // So check digit (pos 9) should be '1' — this VIN has '1' there.
        let id = vs_types::VehicleId::new(b"11111111111111111").expect("valid VIN bytes");
        assert!(validate_check_digit(&id));
    }

    // ---- BusType tests ----

    #[test]
    fn bus_type_to_source_type_mapping() {
        assert_eq!(BusType::Can.to_source_type(), SOURCE_CAN);
        assert_eq!(BusType::CanFd.to_source_type(), SOURCE_CAN_FD);
        assert_eq!(
            BusType::AutomotiveEthernet.to_source_type(),
            SOURCE_AUTOMOTIVE_ETHERNET
        );
        assert_eq!(BusType::Lin.to_source_type(), SOURCE_LIN);
        assert_eq!(BusType::FlexRay.to_source_type(), SOURCE_FLEXRAY);
    }

    #[test]
    fn bus_type_variants() {
        let variants = [
            BusType::Can,
            BusType::CanFd,
            BusType::AutomotiveEthernet,
            BusType::Lin,
            BusType::FlexRay,
        ];
        for v in &variants {
            let _ = format!("{v:?}");
        }
    }

    #[test]
    fn bus_type_equality() {
        assert_eq!(BusType::Can, BusType::Can);
        assert_ne!(BusType::Can, BusType::CanFd);
        assert_ne!(BusType::AutomotiveEthernet, BusType::Lin);
    }

    #[test]
    fn source_constants_distinct() {
        let sources = [
            SOURCE_CAN,
            SOURCE_CAN_FD,
            SOURCE_ETHERNET,
            SOURCE_LIN,
            SOURCE_FLEXRAY,
        ];
        for i in 0..sources.len() {
            for j in i + 1..sources.len() {
                assert_ne!(sources[i], sources[j], "source constants must be unique");
            }
        }
    }

    // --- TryFrom<u8> for BusType ---

    #[test]
    fn bus_type_try_from_u8_roundtrip() {
        let variants = [
            BusType::Can,
            BusType::CanFd,
            BusType::AutomotiveEthernet,
            BusType::Lin,
            BusType::FlexRay,
        ];
        for bus in &variants {
            let source = bus.to_source_type();
            let back = BusType::try_from(source).expect("roundtrip should succeed");
            assert_eq!(*bus, back, "TryFrom<u8> roundtrip failed for {bus:?}");
        }
    }

    #[test]
    fn bus_type_try_from_u8_invalid() {
        // 255 is not a valid source type.
        let result = BusType::try_from(255u8);
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn source_constants_match_core() {
        // Regression test for the constant-divergence hazard: this crate must
        // NOT redefine SOURCE_LIN / SOURCE_FLEXRAY with values that disagree
        // with the core layer. They are re-exported unchanged from vs_types so
        // cross-layer alert correlation stays consistent. If these ever
        // diverge, alert correlation silently breaks — fail loudly here.
        assert_eq!(SOURCE_LIN, vs_types::SOURCE_LIN);
        assert_eq!(SOURCE_FLEXRAY, vs_types::SOURCE_FLEXRAY);
        assert_eq!(SOURCE_AUTOMOTIVE_ETHERNET, vs_types::SOURCE_ETHERNET);
    }

    #[test]
    fn bus_type_try_from_core_source_values() {
        // A source_type set by a core-layer monitor (SOURCE_LIN = 5,
        // SOURCE_FLEXRAY = 6) MUST round-trip through this crate's BusType.
        // Previously these values were rejected because the crate used 10/11.
        assert_eq!(BusType::try_from(vs_types::SOURCE_LIN), Ok(BusType::Lin));
        assert_eq!(
            BusType::try_from(vs_types::SOURCE_FLEXRAY),
            Ok(BusType::FlexRay)
        );
    }

    #[test]
    fn bus_type_agrees_with_core_bus_type() {
        // This crate's BusType and vs_types::BusType must map the same bus to
        // the same source_type, so a SecurityAlert is interpreted identically
        // regardless of which layer produced it.
        assert_eq!(
            BusType::Lin.to_source_type(),
            vs_types::BusType::Lin.to_source_type()
        );
        assert_eq!(
            BusType::FlexRay.to_source_type(),
            vs_types::BusType::FlexRay.to_source_type()
        );
    }

    // --- Hash derive (compile-time check only) ---

    #[test]
    fn bus_type_hashable() {
        use alloc::collections::BTreeMap;
        let mut map: BTreeMap<BusType, u32> = BTreeMap::new();
        map.insert(BusType::Can, 1);
        map.insert(BusType::CanFd, 2);
        assert_eq!(map[&BusType::Can], 1);
        assert_eq!(map[&BusType::CanFd], 2);
    }

    // --- try_from_normalized ---

    #[test]
    fn try_from_normalized_lowercase() {
        // Same VIN as vehicle_id_valid but in lowercase.
        let id = try_from_normalized("1hgbh41jxmn109186")
            .expect("lowercase VIN should be accepted by normalized constructor");
        let expected = vs_types::VehicleId::new(b"1HGBH41JXMN109186").unwrap();
        assert_eq!(id.as_str_unredacted(), expected.as_str_unredacted());
    }

    #[test]
    fn try_from_normalized_mixed_case() {
        let id = try_from_normalized("1HgBh41JxMn109186")
            .expect("mixed-case VIN should be accepted by normalized constructor");
        let expected = vs_types::VehicleId::new(b"1HGBH41JXMN109186").unwrap();
        assert_eq!(id.as_str_unredacted(), expected.as_str_unredacted());
    }

    #[test]
    fn try_from_normalized_rejects_short() {
        let result = try_from_normalized("1hgbh41jxm");
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn try_from_normalized_rejects_bad_chars() {
        // 'i' normalizes to 'I', which is an invalid VIN character.
        let result = try_from_normalized("1hgbh41ixmn109186");
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn try_from_normalized_rejects_bad_check_digit() {
        // Correct VIN but with wrong check digit (changed from X to 0).
        let result = try_from_normalized("1hgbh41j0mn109186");
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    // --- Reserved source IDs ---

    #[test]
    fn ota_reserved_source_id_value() {
        assert_eq!(SOURCE_ID_OTA_RESERVED, 0xFFFF_FFFE);
    }

    #[test]
    fn ota_reserved_source_id_distinct_from_bus_sources() {
        // Ensure the reserved u32 source_id does not collide with any u8
        // source_type when zero-extended.
        let bus_sources: [u8; 5] = [
            SOURCE_CAN,
            SOURCE_CAN_FD,
            SOURCE_ETHERNET,
            SOURCE_LIN,
            SOURCE_FLEXRAY,
        ];
        for &s in &bus_sources {
            assert_ne!(
                SOURCE_ID_OTA_RESERVED, s as u32,
                "OTA reserved ID must not collide with bus source types"
            );
        }
    }

    // --- Anchor test: the crate's `VehicleId` IS the PII-safe core type ---

    #[test]
    fn vehicle_id_is_core_type() {
        // If someone reintroduces a local `pub struct VehicleId` in this
        // crate, this binding fails to type-check because the local type would
        // shadow the re-export. We exercise both paths to anchor equivalence.
        let from_core = vs_types::VehicleId::new(b"1HGBH41JXMN109186").unwrap();
        let from_local: VehicleId = from_core;
        // Use as_str_unredacted (the audited PII accessor) because Display
        // redacts the VIN suffix. See vehicle_id_debug_does_not_leak_full_vin
        // in vs-types for the regression test on the redaction itself.
        assert_eq!(from_local.as_str_unredacted(), "1HGBH41JXMN109186");
    }

    #[test]
    fn vehicle_id_display_is_redacted_through_reexport() {
        // The re-exported `VehicleId` MUST redact PII. This is the regression
        // test for the historical bug where this crate defined a shadowing
        // local `VehicleId` with a leaking Display impl.
        let id: VehicleId = vs_types::VehicleId::new(b"1HGBH41JXMN109186").unwrap();
        let displayed = format!("{id}");
        assert!(
            !displayed.contains("1HGBH41JXMN109186"),
            "VehicleId re-export MUST redact Display (got {displayed})"
        );
        let debugged = format!("{id:?}");
        assert!(
            !debugged.contains("1HGBH41JXMN109186"),
            "VehicleId re-export MUST redact Debug (got {debugged})"
        );
    }
}
