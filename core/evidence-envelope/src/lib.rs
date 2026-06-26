// SPDX-License-Identifier: Apache-2.0
//! Evidence envelope for Craton Shield compliance report payloads.
//!
//! [`Evidence<T>`] wraps a report payload with the metadata an auditor
//! needs to reason about provenance: which standard the payload describes,
//! the schema version of the payload, an opaque generation counter, and the
//! semantic version of the generator crate.
//!
//! This crate is `no_std`, contains no heap allocations, and uses no
//! `unsafe` code.  All field access goes through const-fn accessors so the
//! envelope is immutable from outside the producing crate.
//!
//! # Security
//!
//! **This crate does NOT sign or hash evidence.**
//!
//! **This envelope is structured metadata only.  It provides NO
//! cryptographic binding between the metadata and the wrapped payload `T`.**
//! Despite the name "evidence envelope", nothing in this crate signs,
//! hashes, or otherwise authenticates the payload, and the
//! [`EvidenceMetadata::input_hash`] field is a plain byte array that this
//! crate never validates.  There is no hash chain, no signature, no
//! canonical serialization, and no tamper-detection of any kind.
//!
//! If tamper-evidence is required, producers MUST sign the envelope
//! externally -- for example by computing a `vs-crypto` ECDSA signature
//! over a stable serialization (including a hash of the full struct) and
//! distributing that signature alongside the envelope.  Consumers MUST
//! verify that external signature before trusting any field on
//! [`Evidence<T>`].
//!
//! Treat an unverified `Evidence<T>` exactly as you would treat its raw
//! payload: untrusted input.
//!
//! # Notes
//!
//! The compatibility [`EvidenceMetadata::schema_version`] field packs the
//! `(major, minor, patch)` triple as `(major << 16) | (minor << 8) | patch`
//! -- 8 bits per component.  [`SchemaVersion`] itself stores each component
//! as a `u16` for forward compatibility, but values above `255` cannot
//! round-trip through this packed encoding.  The infallible
//! [`SchemaVersion::new`] constructor saturates each component at `255`
//! (with a `debug_assert!` in debug builds); use [`SchemaVersion::try_new`]
//! to reject over-range inputs explicitly.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Compliance standard that a payload provides evidence for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Standard {
    /// IEC 62304 -- Medical device software lifecycle.
    Iec62304,
    /// IEC 62443-4-2 -- Industrial cybersecurity component requirements.
    Iec62443,
    /// ISO/SAE 21434 -- Road vehicles cybersecurity engineering.
    Iso21434,
}

impl Standard {
    /// Human-readable label for this standard.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Iec62304 => "IEC 62304",
            Self::Iec62443 => "IEC 62443-4-2",
            Self::Iso21434 => "ISO/SAE 21434",
        }
    }
}

/// Semantic version triple `(major, minor, patch)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SchemaVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

impl SchemaVersion {
    /// Construct a new schema version.
    ///
    /// **Saturates silently to `255`** in each component if the input
    /// exceeds the 8-bit slot used by the compatibility
    /// [`EvidenceMetadata::schema_version`] packed encoding
    /// (`(major << 16) | (minor << 8) | patch`).  This keeps `new` an
    /// infallible `const fn` while preventing the previous
    /// truncate-mod-256 data-loss bug.  In debug builds a
    /// `debug_assert!` fires before saturation so the over-range input is
    /// caught during development.  For fallible construction that rejects
    /// over-range inputs, use [`Self::try_new`].
    #[must_use]
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        debug_assert!(
            major <= 255 && minor <= 255 && patch <= 255,
            "SchemaVersion component exceeds 255; will saturate. Use try_new() to reject.",
        );
        Self {
            major: if major > 255 { 255 } else { major },
            minor: if minor > 255 { 255 } else { minor },
            patch: if patch > 255 { 255 } else { patch },
        }
    }

    /// Fallible companion to [`Self::new`].
    ///
    /// Returns `None` if any component exceeds `255` (the upper bound of
    /// the 8-bit slot used by the compatibility
    /// [`EvidenceMetadata::schema_version`] packed encoding); otherwise
    /// returns the constructed version with no saturation.
    #[must_use]
    pub const fn try_new(major: u16, minor: u16, patch: u16) -> Option<Self> {
        if major > 255 || minor > 255 || patch > 255 {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
        })
    }

    /// Major component of the schema version.
    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Minor component of the schema version.
    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }

    /// Patch component of the schema version.
    #[must_use]
    pub const fn patch(self) -> u16 {
        self.patch
    }
}

/// Error returned by fallible [`GeneratorVersion`] constructors when the
/// supplied string is longer than the 16-byte internal buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneratorVersionTooLong {
    /// The length, in bytes, of the offending input.
    pub input_len: usize,
}

/// Opaque generator version, taken from `env!("CARGO_PKG_VERSION")` by the
/// producing crate.  Stored as bytes so this crate stays `no_std` and
/// allocation-free; consumers can compare or display via [`Self::as_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneratorVersion {
    bytes: [u8; 16],
    len: u8,
}

impl GeneratorVersion {
    /// Build a `GeneratorVersion` from a `&str`, typically
    /// `env!("CARGO_PKG_VERSION")`.
    ///
    /// **Truncates silently to 16 bytes** if the input is longer.  For
    /// fallible construction that rejects over-long inputs, use
    /// [`Self::try_from_str`].
    #[must_use]
    pub const fn from_str(s: &str) -> Self {
        let src = s.as_bytes();
        let mut bytes = [0u8; 16];
        let mut i = 0;
        let max = if src.len() < 16 { src.len() } else { 16 };
        while i < max {
            bytes[i] = src[i];
            i += 1;
        }
        Self {
            bytes,
            len: max as u8,
        }
    }

    /// Fallible companion to [`Self::from_str`].
    ///
    /// Returns [`GeneratorVersionTooLong`] if `s.len() > 16`; otherwise
    /// returns the constructed version with no truncation.
    pub const fn try_from_str(s: &str) -> Result<Self, GeneratorVersionTooLong> {
        if s.len() > 16 {
            return Err(GeneratorVersionTooLong { input_len: s.len() });
        }
        Ok(Self::from_str(s))
    }

    /// Borrow the version as a UTF-8 string.
    ///
    /// Internally this re-validates the stored bytes as UTF-8 on every
    /// call.  The cost is bounded (at most 16 bytes scanned) and the buffer
    /// is always populated from a `&str` source, so in practice this is a
    /// fast no-op check.  We accept the cost rather than introduce a
    /// `validated: bool` flag -- the alternative (`from_utf8_unchecked`)
    /// requires `unsafe`, which is forbidden crate-wide.
    ///
    /// If the source string was truncated mid-codepoint (very rare for
    /// semver-formatted versions, all ASCII), returns the longest valid
    /// UTF-8 prefix.
    #[must_use]
    pub fn as_str(&self) -> &str {
        let raw = &self.bytes[..self.len as usize];
        match core::str::from_utf8(raw) {
            Ok(s) => s,
            Err(e) => {
                let valid_up_to = e.valid_up_to();
                core::str::from_utf8(&raw[..valid_up_to]).unwrap_or("")
            }
        }
    }

    /// Raw byte view of the version string (no trailing NUL).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

/// Opaque, caller-supplied "when was this generated" counter.  Has no
/// inherent unit -- callers may use a wall clock, a tick counter, or a
/// monotonic event sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GeneratedAt(u64);

impl GeneratedAt {
    /// Wrap a raw `u64` counter value as a [`GeneratedAt`].
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Extract the wrapped `u64` counter value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Generic evidence envelope wrapping a report payload `T`.
///
/// Fields are private; access them through the const-fn accessors.  Build
/// instances with [`Evidence::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence<T> {
    standard: Standard,
    schema_version: SchemaVersion,
    generated_at: GeneratedAt,
    generator_version: GeneratorVersion,
    assessor_id: [u8; 16],
    input_hash: [u8; 32],
    payload: T,
}

impl<T> Evidence<T> {
    /// Construct a new envelope wrapping `payload`.
    ///
    /// `assessor_id` and `input_hash` default to zero; use
    /// [`Self::with_metadata`] to populate them.
    pub const fn new(
        standard: Standard,
        schema_version: SchemaVersion,
        generated_at: GeneratedAt,
        generator_version: GeneratorVersion,
        payload: T,
    ) -> Self {
        Self {
            standard,
            schema_version,
            generated_at,
            generator_version,
            assessor_id: [0u8; 16],
            input_hash: [0u8; 32],
            payload,
        }
    }

    /// Standard this envelope provides evidence for.
    #[must_use]
    pub const fn standard(&self) -> Standard {
        self.standard
    }

    /// Schema version of the wrapped payload.
    #[must_use]
    pub const fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Caller-supplied generation counter.
    #[must_use]
    pub const fn generated_at(&self) -> GeneratedAt {
        self.generated_at
    }

    /// Version of the crate that produced the wrapped payload.
    #[must_use]
    pub const fn generator_version(&self) -> &GeneratorVersion {
        &self.generator_version
    }

    /// Borrow the wrapped payload.
    #[must_use]
    pub const fn payload(&self) -> &T {
        &self.payload
    }

    /// Consume the envelope and return the wrapped payload.
    #[must_use]
    pub fn into_payload(self) -> T {
        self.payload
    }

    /// Compatibility accessor — returns an `EvidenceMetadata` snapshot
    /// assembled from the envelope's stored fields. Provided so callers
    /// authored against the alternate metadata-struct API can read the
    /// stored values without per-field accessor calls.
    ///
    /// `assessor_id` and `input_hash` reflect the values currently stored
    /// on the envelope: they are zero for an envelope built with
    /// [`Self::new`] (which does not accept them) and carry the
    /// caller-supplied values for an envelope built with
    /// [`Self::with_metadata`].
    #[must_use]
    pub fn metadata(&self) -> EvidenceMetadata {
        let mut tool_version = [0u8; 16];
        let bytes = self.generator_version.as_bytes();
        let n = bytes.len().min(16);
        tool_version[..n].copy_from_slice(&bytes[..n]);
        EvidenceMetadata {
            generated_at_ns: self.generated_at.value(),
            assessor_id: self.assessor_id,
            tool_version,
            input_hash: self.input_hash,
            schema_version: ((u32::from(self.schema_version.major()) << 16)
                | (u32::from(self.schema_version.minor()) << 8)
                | u32::from(self.schema_version.patch())),
        }
    }

    /// Compatibility accessor — returns the attached signature, if any.
    /// At 0.7.0 the envelope carries no cryptographic signature (see the
    /// crate-level `# Security` section), so this always returns `None`.
    #[must_use]
    pub const fn signature(&self) -> Option<&[u8]> {
        None
    }
}

impl<T: Copy> Copy for Evidence<T> {}

/// Compatibility metadata struct used by report crates that were authored
/// against the (alternate) `EvidenceMetadata` API contract.  Carries the
/// same information as the per-field arguments of [`Evidence::new`] but as
/// a single struct.
///
/// `schema_version` is encoded as `(major << 16) | (minor << 8) | patch`,
/// each component occupying 8 bits.  Components above 255 are unsupported
/// in this encoding.
///
/// Note that [`Self::input_hash`] is stored verbatim and is **not**
/// verified by this crate; see the crate-level `# Security` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceMetadata {
    /// Caller-supplied nanosecond timestamp for the generation event.
    pub generated_at_ns: u64,
    /// Free-form 16-byte identifier for the assessor.
    pub assessor_id: [u8; 16],
    /// 16-byte buffer carrying the producing crate's version string.
    pub tool_version: [u8; 16],
    /// 32-byte hash of the inputs that produced the payload.  Opaque to
    /// this crate -- no validation is performed.
    pub input_hash: [u8; 32],
    /// Packed schema version: `(major << 16) | (minor << 8) | patch`.
    pub schema_version: u32,
}

impl EvidenceMetadata {
    /// Construct with all fields zeroed.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            generated_at_ns: 0,
            assessor_id: [0u8; 16],
            tool_version: [0u8; 16],
            input_hash: [0u8; 32],
            schema_version: 0,
        }
    }
}

impl<T> Evidence<T> {
    /// Construct an envelope from the compatibility [`EvidenceMetadata`]
    /// shape.
    ///
    /// The caller must pass the [`Standard`] explicitly -- it is not
    /// encoded in [`EvidenceMetadata`].  `tool_version` is mapped through
    /// [`GeneratorVersion::from_bytes`], `generated_at_ns` becomes the
    /// [`GeneratedAt`] value, and `schema_version` is unpacked as
    /// `major = (v >> 16) & 0xFF`, `minor = (v >> 8) & 0xFF`,
    /// `patch = v & 0xFF`.
    #[must_use]
    pub fn with_metadata(payload: T, standard: Standard, metadata: EvidenceMetadata) -> Self {
        let gv = GeneratorVersion::from_bytes(metadata.tool_version);
        let v = metadata.schema_version;
        Self {
            standard,
            schema_version: SchemaVersion::new(
                ((v >> 16) & 0xFF) as u16,
                ((v >> 8) & 0xFF) as u16,
                (v & 0xFF) as u16,
            ),
            generated_at: GeneratedAt::new(metadata.generated_at_ns),
            generator_version: gv,
            assessor_id: metadata.assessor_id,
            input_hash: metadata.input_hash,
            payload,
        }
    }
}

impl GeneratorVersion {
    /// Construct a `GeneratorVersion` from a raw 16-byte buffer.
    ///
    /// **NUL-truncation:** `len` is computed as the position of the first
    /// `0` byte, or `16` if none is present.  This means a payload like
    /// `b"0.7\0extra"` is silently treated as `b"0.7"`.  For inputs that
    /// may legitimately contain interior NULs, use
    /// [`Self::from_bytes_with_len`] and pass an explicit length.
    #[must_use]
    pub const fn from_bytes(buf: [u8; 16]) -> Self {
        let mut i = 0usize;
        let mut len = 16u8;
        while i < 16 {
            if buf[i] == 0 {
                len = i as u8;
                i = 16;
            } else {
                i += 1;
            }
        }
        Self { bytes: buf, len }
    }

    /// Construct a `GeneratorVersion` from a 16-byte buffer with an
    /// explicit length.
    ///
    /// Unlike [`Self::from_bytes`] this does **not** scan for a NUL
    /// terminator, so interior NULs are preserved.  `len` is clamped to
    /// `16` if it exceeds the buffer.
    #[must_use]
    pub const fn from_bytes_with_len(buf: [u8; 16], len: usize) -> Self {
        let clamped = if len > 16 { 16 } else { len };
        Self {
            bytes: buf,
            len: clamped as u8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_labels() {
        assert_eq!(Standard::Iec62304.label(), "IEC 62304");
        assert_eq!(Standard::Iec62443.label(), "IEC 62443-4-2");
        assert_eq!(Standard::Iso21434.label(), "ISO/SAE 21434");
    }

    #[test]
    fn schema_version_components() {
        let v = SchemaVersion::new(1, 2, 3);
        assert_eq!(v.major(), 1);
        assert_eq!(v.minor(), 2);
        assert_eq!(v.patch(), 3);
    }

    #[test]
    fn generator_version_roundtrip() {
        let v = GeneratorVersion::from_str("0.7.0");
        assert_eq!(v.as_str(), "0.7.0");
        assert_eq!(v.as_bytes(), b"0.7.0");
    }

    #[test]
    fn generator_version_truncates() {
        let v = GeneratorVersion::from_str("0.7.0-extra-suffix-too-long");
        assert_eq!(v.as_bytes().len(), 16);
    }

    #[test]
    fn generator_version_try_from_str_rejects_overlong() {
        let err = GeneratorVersion::try_from_str("0.7.0-extra-suffix-too-long").unwrap_err();
        assert_eq!(err.input_len, "0.7.0-extra-suffix-too-long".len());
    }

    #[test]
    fn generator_version_try_from_str_accepts_short() {
        let v = GeneratorVersion::try_from_str("0.7.0").unwrap();
        assert_eq!(v.as_str(), "0.7.0");
    }

    #[test]
    fn from_bytes_truncates_at_nul() {
        let mut buf = [0u8; 16];
        buf[0] = b'0';
        buf[1] = b'.';
        buf[2] = b'7';
        // buf[3] is NUL; everything after is ignored.
        buf[4] = b'X';
        let v = GeneratorVersion::from_bytes(buf);
        assert_eq!(v.as_bytes(), b"0.7");
    }

    #[test]
    fn from_bytes_with_len_preserves_interior_nul() {
        let mut buf = [0u8; 16];
        buf[0] = b'a';
        // buf[1] is NUL
        buf[2] = b'b';
        let v = GeneratorVersion::from_bytes_with_len(buf, 3);
        assert_eq!(v.as_bytes().len(), 3);
        assert_eq!(v.as_bytes()[1], 0);
    }

    #[test]
    fn from_bytes_with_len_clamps_to_sixteen() {
        let buf = [b'x'; 16];
        let v = GeneratorVersion::from_bytes_with_len(buf, 99);
        assert_eq!(v.as_bytes().len(), 16);
    }

    #[test]
    fn evidence_accessors() {
        let env = Evidence::new(
            Standard::Iec62304,
            SchemaVersion::new(0, 9, 0),
            GeneratedAt::new(42),
            GeneratorVersion::from_str("0.7.0"),
            123u32,
        );
        assert_eq!(env.standard(), Standard::Iec62304);
        assert_eq!(env.schema_version(), SchemaVersion::new(0, 9, 0));
        assert_eq!(env.generated_at(), GeneratedAt::new(42));
        assert_eq!(env.generator_version().as_str(), "0.7.0");
        assert_eq!(*env.payload(), 123);
        assert_eq!(env.into_payload(), 123);
    }

    #[test]
    fn with_metadata_uses_supplied_standard_and_unpacks_schema() {
        // schema 1.2.3 packed as (1<<16)|(2<<8)|3
        let mut md = EvidenceMetadata::empty();
        md.generated_at_ns = 99;
        md.schema_version = (1u32 << 16) | (2u32 << 8) | 3u32;
        md.tool_version[0] = b'0';
        md.tool_version[1] = b'.';
        md.tool_version[2] = b'7';
        let env = Evidence::with_metadata(7u8, Standard::Iso21434, md);
        assert_eq!(env.standard(), Standard::Iso21434);
        assert_eq!(env.schema_version(), SchemaVersion::new(1, 2, 3));
        assert_eq!(env.generated_at(), GeneratedAt::new(99));
        assert_eq!(env.generator_version().as_str(), "0.7");
        assert_eq!(*env.payload(), 7);
    }

    #[test]
    fn schema_version_try_new_rejects_overlong_components() {
        // Components > 255 cannot fit in the 8-bit packed encoding used by
        // EvidenceMetadata::schema_version, so try_new must refuse them.
        assert!(SchemaVersion::try_new(256, 0, 0).is_none());
        assert!(SchemaVersion::try_new(0, 256, 0).is_none());
        assert!(SchemaVersion::try_new(0, 0, 256).is_none());
        assert!(SchemaVersion::try_new(u16::MAX, u16::MAX, u16::MAX).is_none());
        // Boundary: 255 is the largest accepted value.
        assert_eq!(
            SchemaVersion::try_new(255, 255, 255),
            Some(SchemaVersion::new(255, 255, 255)),
        );
    }

    #[test]
    fn schema_version_metadata_roundtrip_lossless_within_8bit_range() {
        // Within the supported 0..=255 range, metadata() and with_metadata
        // must be exact inverses.
        for (maj, min, pat) in [(0u16, 0, 0), (1, 2, 3), (255, 255, 255), (10, 0, 200)] {
            let env = Evidence::new(
                Standard::Iec62304,
                SchemaVersion::new(maj, min, pat),
                GeneratedAt::new(0),
                GeneratorVersion::from_str("0.7.0"),
                0u8,
            );
            let md = env.metadata();
            let rebuilt = Evidence::with_metadata(0u8, Standard::Iec62304, md);
            assert_eq!(rebuilt.schema_version(), SchemaVersion::new(maj, min, pat));
        }
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn schema_version_overlong_component_saturates_in_release() {
        // In release builds, new() saturates instead of panicking.  The
        // resulting envelope's schema therefore packs cleanly into the
        // 8-bit-per-component layout used by metadata()/with_metadata,
        // which is the property forensic consumers depend on.  This
        // documents the asymmetry-fix: previously `as u8` truncation would
        // turn 256 into 0; now saturation turns 256 into 255 so the value
        // round-trips through metadata().
        let v = SchemaVersion::new(256, 300, 1000);
        assert_eq!(v.major(), 255);
        assert_eq!(v.minor(), 255);
        assert_eq!(v.patch(), 255);
        let env = Evidence::new(
            Standard::Iec62304,
            v,
            GeneratedAt::new(0),
            GeneratorVersion::from_str("0.7.0"),
            0u8,
        );
        let rebuilt = Evidence::with_metadata(0u8, Standard::Iec62304, env.metadata());
        assert_eq!(rebuilt.schema_version(), SchemaVersion::new(255, 255, 255));
    }

    #[test]
    fn evidence_is_copy_when_payload_is_copy() {
        // If this compiles, `Evidence<u32>` is Copy.
        let env = Evidence::new(
            Standard::Iec62304,
            SchemaVersion::new(0, 9, 0),
            GeneratedAt::new(42),
            GeneratorVersion::from_str("0.7.0"),
            123u32,
        );
        let copy = env;
        let _orig_still_usable = env.payload();
        assert_eq!(*copy.payload(), 123);
    }
}
