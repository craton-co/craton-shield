# vs-evidence-envelope

Standardized metadata envelope for Craton Shield compliance report payloads
(IEC 62304, IEC 62443, ISO/SAE 21434, ...).

The `Evidence<T>` type wraps a report payload with:

- a `Standard` discriminant (which standard the payload is evidence for),
- a `SchemaVersion` (semantic version of the payload schema),
- a `GeneratedAt` monotonic counter (caller-supplied opaque timestamp),
- a `GeneratorVersion` (crate version that produced the payload).

Fields are private; consumers must use the constructor (`Evidence::new`
or `Evidence::with_metadata`) and read them back through the const-fn
accessors on `Evidence<T>`. This prevents accidental mutation of the
metadata and gives downstream auditors a stable contract.

`#![no_std]`, zero-allocation, `#![forbid(unsafe_code)]` (stronger than
`deny`: no `unsafe` block can ever appear in this crate).

## Security

**This envelope provides NO cryptographic binding between the metadata
and the wrapped payload.** Despite the name "evidence envelope", nothing
in this crate signs, hashes, or authenticates the payload, and
`EvidenceMetadata::input_hash` is a plain byte array that this crate
never validates.

If tamper-evidence is required, producers MUST sign the envelope
externally -- for example by computing a `vs-crypto` ECDSA signature
over a stable serialization (including a hash of the full struct) and
distributing that signature alongside the envelope. Consumers MUST
verify that external signature before trusting any field on
`Evidence<T>`.

Treat an unverified `Evidence<T>` exactly as you would treat its raw
payload: untrusted input.

## `EvidenceMetadata` / `with_metadata`

For producers that prefer to assemble metadata as a single struct,
`EvidenceMetadata` carries the same information as the per-field
arguments of `Evidence::new`:

```rust,ignore
let env = Evidence::with_metadata(payload, Standard::Iso21434, metadata);
```

Notable details:

- The caller passes `Standard` explicitly -- it is **not** stored inside
  `EvidenceMetadata`.
- `schema_version: u32` is packed as `(major << 16) | (minor << 8) | patch`,
  each component limited to 8 bits.
- `tool_version: [u8; 16]` is mapped through
  `GeneratorVersion::from_bytes`, which treats the first NUL byte as
  end-of-string. Use `GeneratorVersion::from_bytes_with_len` if you need
  to preserve interior NULs.
- `input_hash: [u8; 32]` is opaque to this crate -- see Security above.

## License

Apache-2.0.
