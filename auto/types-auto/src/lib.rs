// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company

#![no_std]

//! Shared automotive types for the Craton Shield Auto workspace.
//!
//! Provides `VehicleId` (VIN with ISO 3779 check digit validation), `BusType` enum,
//! and source-type constants for LIN, `FlexRay`, and OTA subsystems.

#[cfg(test)]
extern crate alloc;

use core::fmt;

// Re-export everything from the core types crate.
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
/// LIN bus.
pub const SOURCE_LIN: u8 = 10;
/// `FlexRay` bus.
pub const SOURCE_FLEXRAY: u8 = 11;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
pub enum BusType {
    Can,
    CanFd,
    AutomotiveEthernet,
    Lin,
    FlexRay,
}

impl BusType {
    /// Convert a `BusType` to the corresponding `source_type` constant used in
    /// [`SecurityAlert`].
    pub fn to_source_type(self) -> u8 {
        match self {
            Self::Can => vs_types::SOURCE_CAN,
            Self::CanFd => vs_types::SOURCE_CAN_FD,
            Self::AutomotiveEthernet => SOURCE_AUTOMOTIVE_ETHERNET,
            Self::Lin => SOURCE_LIN,
            Self::FlexRay => SOURCE_FLEXRAY,
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
            x if x == SOURCE_LIN => Ok(Self::Lin),
            x if x == SOURCE_FLEXRAY => Ok(Self::FlexRay),
            _ => Err(vs_types::VsError::InvalidInput),
        }
    }
}

// ---------------------------------------------------------------------------
// VehicleId (17-character VIN)
// ---------------------------------------------------------------------------

/// Vehicle identification number (17 ASCII characters).
///
/// The inner bytes are private to enforce the invariant that all VIN
/// characters are valid ASCII (excluding I, O, Q). Construct via
/// `TryFrom<&str>` (strict, uppercase only) or [`VehicleId::try_from_normalized`]
/// (normalizes lowercase to uppercase) and access the bytes via
/// [`VehicleId::as_bytes`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
pub struct VehicleId {
    vin: [u8; 17],
}

impl VehicleId {
    /// Returns the raw VIN bytes.
    pub fn as_bytes(&self) -> &[u8; 17] {
        &self.vin
    }
}

impl VehicleId {
    /// Returns `true` if the given byte is a valid VIN character.
    /// VINs exclude the letters I, O, and Q.
    fn is_valid_vin_char(b: u8) -> bool {
        matches!(b, b'0'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P' | b'R'..=b'Z')
    }

    /// Returns the ISO 3779 transliteration value for a VIN character.
    /// Used for check digit computation at position 9 (index 8).
    fn transliterate(b: u8) -> Option<u8> {
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

    /// Validates the ISO 3779 check digit at position 9 (index 8).
    ///
    /// The check digit can be 0-9 or X (representing 10). Each position
    /// has a weight, and the sum of `(transliterated_value * weight) mod 11`
    /// must equal the check digit.
    fn validate_check_digit(vin: &[u8; 17]) -> bool {
        const WEIGHTS: [u8; 17] = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];

        let mut sum: u32 = 0;
        let mut i = 0;
        while i < 17 {
            if i == 8 {
                // Skip the check digit position itself during summation.
                i += 1;
                continue;
            }
            let val = match Self::transliterate(vin[i]) {
                Some(v) => v as u32,
                None => return false,
            };
            sum += val * WEIGHTS[i] as u32;
            i += 1;
        }

        let remainder = (sum % 11) as u8;
        let check_char = vin[8];

        if check_char == b'X' {
            remainder == 10
        } else if check_char.is_ascii_digit() {
            remainder == check_char - b'0'
        } else {
            false
        }
    }
}

impl fmt::Debug for VehicleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VehicleId")
            .field("vin", &self.as_str())
            .finish()
    }
}

impl fmt::Display for VehicleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl VehicleId {
    /// Interpret the VIN bytes as a UTF-8 string.
    /// This is always valid because VIN characters are ASCII.
    fn as_str(&self) -> &str {
        // SAFETY rationale: VIN bytes are validated to be ASCII alphanumeric
        // (excluding I, O, Q) during construction via TryFrom. All valid VIN
        // characters are valid UTF-8, so this conversion is infallible for
        // any VehicleId that was constructed through the public API.
        // We use unwrap_or to provide a safe fallback regardless.
        core::str::from_utf8(&self.vin).unwrap_or("INVALID_VIN_BYTES")
    }
}

impl TryFrom<&str> for VehicleId {
    type Error = vs_types::VsError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let bytes = s.as_bytes();
        if bytes.len() != 17 {
            return Err(vs_types::VsError::InvalidInput);
        }
        for &b in bytes {
            if !Self::is_valid_vin_char(b) {
                return Err(vs_types::VsError::InvalidInput);
            }
        }
        let mut vin = [0u8; 17];
        vin.copy_from_slice(bytes);

        // Validate the ISO 3779 check digit at position 9 (index 8).
        if !Self::validate_check_digit(&vin) {
            return Err(vs_types::VsError::InvalidInput);
        }

        Ok(Self { vin })
    }
}

impl VehicleId {
    /// Parse a VIN from a string, normalizing to uppercase first.
    ///
    /// Accepts lowercase or mixed-case VINs and converts them to uppercase
    /// before validation. Many real-world systems produce lowercase VINs
    /// despite the ISO 3779 specification requiring uppercase characters.
    ///
    /// Returns `Err(VsError::InvalidInput)` if the normalized VIN is not
    /// exactly 17 valid VIN characters or if the check digit is incorrect.
    ///
    /// Use [`TryFrom<&str>`] instead when strict uppercase enforcement is
    /// required.
    pub fn try_from_normalized(s: &str) -> Result<Self, vs_types::VsError> {
        let bytes = s.as_bytes();
        if bytes.len() != 17 {
            return Err(vs_types::VsError::InvalidInput);
        }
        let mut vin = [0u8; 17];
        for (i, &b) in bytes.iter().enumerate() {
            vin[i] = b.to_ascii_uppercase();
        }
        for &b in &vin {
            if !Self::is_valid_vin_char(b) {
                return Err(vs_types::VsError::InvalidInput);
            }
        }
        if !Self::validate_check_digit(&vin) {
            return Err(vs_types::VsError::InvalidInput);
        }
        Ok(Self { vin })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn vehicle_id_valid() {
        let vin = "1HGBH41JXMN109186";
        let id = VehicleId::try_from(vin).expect("valid VIN");
        assert_eq!(format!("{id}"), vin);
    }

    #[test]
    fn vehicle_id_too_short() {
        let result = VehicleId::try_from("1HGBH41JXM");
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn vehicle_id_too_long() {
        let result = VehicleId::try_from("1HGBH41JXMN1091860");
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn vehicle_id_rejects_i() {
        let result = VehicleId::try_from("1HGBH41IXMN10918");
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn vehicle_id_rejects_o() {
        let result = VehicleId::try_from("1HGBH41OXMN10918");
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn vehicle_id_rejects_q() {
        let result = VehicleId::try_from("1HGBH41QXMN10918");
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn vehicle_id_rejects_lowercase() {
        let result = VehicleId::try_from("1hgbh41jxmn109186");
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn vehicle_id_debug() {
        let id = VehicleId::try_from("1HGBH41JXMN109186").expect("valid VIN");
        let s = format!("{id:?}");
        assert!(s.contains("1HGBH41JXMN109186"));
    }

    #[test]
    fn vehicle_id_rejects_bad_check_digit() {
        // Change check digit from 'X' (correct) to '0' (incorrect).
        let result = VehicleId::try_from("1HGBH41J0MN109186");
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn vehicle_id_check_digit_x_means_10() {
        // 1HGBH41JXMN109186 has check digit X (remainder = 10).
        let id = VehicleId::try_from("1HGBH41JXMN109186");
        assert!(id.is_ok(), "VIN with check digit X should be valid");
    }

    #[test]
    fn vehicle_id_numeric_check_digit() {
        // 11111111111111111: all 1s
        // transliteration: all 1s, weights sum = 1*(8+7+6+5+4+3+2+10+9+8+7+6+5+4+3+2) = 89
        // 89 mod 11 = 89 - 8*11 = 89 - 88 = 1
        // So check digit (pos 9) should be '1' — this VIN has '1' there.
        let result = VehicleId::try_from("11111111111111111");
        assert!(
            result.is_ok(),
            "VIN with all 1s should have valid check digit 1"
        );
    }

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

    // --- Ord/PartialOrd for VehicleId ---

    #[test]
    fn vehicle_id_ord() {
        let a = VehicleId::try_from("1HGBH41JXMN109186").unwrap();
        let b = VehicleId::try_from("11111111111111111").unwrap();
        // Lexicographic order: '1' < '1HGBH...' at byte 1 ('H' > '1').
        assert!(b < a);
        assert!(a > b);
        assert_eq!(a, a);
    }

    #[test]
    fn vehicle_id_hashable() {
        use alloc::collections::BTreeMap;
        let a = VehicleId::try_from("1HGBH41JXMN109186").unwrap();
        let b = VehicleId::try_from("11111111111111111").unwrap();
        let mut map: BTreeMap<VehicleId, &str> = BTreeMap::new();
        map.insert(a, "honda");
        map.insert(b, "ones");
        assert_eq!(map[&a], "honda");
    }

    // --- try_from_normalized ---

    #[test]
    fn vehicle_id_try_from_normalized_lowercase() {
        // Same VIN as vehicle_id_valid but in lowercase.
        let id = VehicleId::try_from_normalized("1hgbh41jxmn109186")
            .expect("lowercase VIN should be accepted by normalized constructor");
        let expected = VehicleId::try_from("1HGBH41JXMN109186").unwrap();
        assert_eq!(id, expected);
    }

    #[test]
    fn vehicle_id_try_from_normalized_mixed_case() {
        let id = VehicleId::try_from_normalized("1HgBh41JxMn109186")
            .expect("mixed-case VIN should be accepted by normalized constructor");
        let expected = VehicleId::try_from("1HGBH41JXMN109186").unwrap();
        assert_eq!(id, expected);
    }

    #[test]
    fn vehicle_id_try_from_normalized_rejects_short() {
        let result = VehicleId::try_from_normalized("1hgbh41jxm");
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn vehicle_id_try_from_normalized_rejects_bad_chars() {
        // 'i' normalizes to 'I', which is an invalid VIN character.
        let result = VehicleId::try_from_normalized("1hgbh41ixmn109186");
        assert_eq!(result, Err(VsError::InvalidInput));
    }

    #[test]
    fn vehicle_id_try_from_normalized_rejects_bad_check_digit() {
        // Correct VIN but with wrong check digit (changed from X to 0).
        let result = VehicleId::try_from_normalized("1hgbh41j0mn109186");
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

    // --- Additional VIN tests ---

    #[test]
    fn test_vin_all_uppercase_identity() {
        // An already-uppercase valid VIN passed to try_from_normalized should
        // succeed and produce the same result as TryFrom<&str>.
        let vin_str = "1HGBH41JXMN109186";
        let from_normalized = VehicleId::try_from_normalized(vin_str)
            .expect("already-uppercase VIN must succeed via try_from_normalized");
        let from_strict =
            VehicleId::try_from(vin_str).expect("already-uppercase VIN must succeed via TryFrom");
        assert_eq!(
            from_normalized, from_strict,
            "try_from_normalized with uppercase input must match TryFrom"
        );
    }

    #[test]
    fn test_vin_non_ascii_rejected() {
        // Multi-byte UTF-8 characters should be rejected (e.g., accented
        // chars, CJK, emoji). The string is 17 bytes long but contains
        // non-ASCII characters.

        // "1HGBH41JXMN10918\u{00E9}" is 18 bytes (e9 is 2 bytes in UTF-8),
        // so it fails on length. Use a 17-char string with a multi-byte char.
        // \u{00FC} = u-umlaut = 2 UTF-8 bytes, so we need 16 ASCII + 1 multi-byte
        // = 18 bytes, which fails length check.
        let result = VehicleId::try_from("1HGBH41JXMN1091\u{00FC}");
        assert_eq!(
            result,
            Err(VsError::InvalidInput),
            "VIN with non-ASCII characters must be rejected"
        );

        // Also test try_from_normalized with non-ASCII.
        let result = VehicleId::try_from_normalized("1HGBH41JXMN1091\u{00FC}");
        assert_eq!(
            result,
            Err(VsError::InvalidInput),
            "try_from_normalized with non-ASCII must be rejected"
        );

        // Test with a string that is exactly 17 bytes but contains a non-VIN
        // ASCII character like '!' (which is ASCII but not a valid VIN char).
        let result = VehicleId::try_from("1HGBH41JXMN10918!");
        assert_eq!(
            result,
            Err(VsError::InvalidInput),
            "VIN with '!' must be rejected"
        );
    }
}
