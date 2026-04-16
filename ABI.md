# Craton Shield C ABI Contract

This document defines the **C ABI contract** for the Craton Shield FFI
crates (`vs-ffi` and `vs-ffi-auto`). It is the authoritative reference
for downstream C/C++ integrators and for maintainers proposing changes
to the FFI surface.

The Rust API of every workspace crate follows Cargo semver. The **C
ABI** — the in-memory layout of `#[repr(C)]` structs and the signatures
of `extern "C"` functions — is tracked **separately** via the packed
`VS_ABI_VERSION` constant.

---

## 1. The `VS_ABI_VERSION` constant

```
VS_ABI_VERSION = (major << 16) | (minor << 8) | patch
```

Current value: **`0x00010000`** (ABI 1.0.0).

There are two sources of this constant:

| Component        | File                                      | Symbol               |
|------------------|-------------------------------------------|----------------------|
| Core C header    | `core/include/cratonshield.h`             | `VS_ABI_VERSION`     |
| Core Rust crate  | `core/ffi/src/lib.rs`                     | `VS_ABI_VERSION`     |
| Core query fn    | `core/ffi/src/lib.rs`                     | `vs_abi_version()`   |
| Auto C header    | `auto/ffi-auto/vs_auto.h`                 | `VS_ABI_VERSION`     |
| Auto Rust crate  | `auto/ffi-auto/src/lib.rs`                | `VS_ABI_VERSION`     |
| Auto query fn    | `auto/ffi-auto/src/lib.rs`                | `vs_auto_abi_version()` |

The C header is the **single source of truth**. The Rust crates contain
`const _: () = assert!(VS_ABI_VERSION == 0x00010000)` compile-time
assertions; if the header and the Rust constant diverge, the build
fails. **Always bump both in the same commit.**

The two ABIs (core and auto) are versioned **together**: a major bump
applies to both. This simplifies the contract for integrators who link
both libraries.

---

## 2. Versioning policy

Each component of `VS_ABI_VERSION` has a precise meaning. The policy
borrows from semver but is strictly about the *binary* contract.

### Major bump (`0x00010000 -> 0x00020000`)

**Breaking ABI change.** Pre-existing C consumers that linked against
the previous major version MUST refuse to dispatch.

Triggers for a major bump include, but are not limited to:

- Removing or renaming any exported `vs_*` function.
- Changing the signature of any exported `vs_*` function (parameter
  types, parameter order, return type).
- Removing, renaming, reordering, or retyping any field of a
  `#[repr(C)]` struct exposed across the boundary.
- Changing the meaning of an existing error code or result-code value.
- Changing the calling convention of an exported function.
- Changing the size of any struct exposed across the boundary, unless
  the change is to a field explicitly documented as **reserved**.

### Minor bump (`0x00010000 -> 0x00010100`)

**Backward-compatible addition.** Old consumers continue to link and
dispatch correctly.

- Adding a new exported `vs_*` function.
- Adding a new error code with a numerically distinct value.
- Adding a new field at the **end** of a `#[repr(C)]` struct, only when
  the struct ABI was explicitly documented to allow trailing additions
  (see §4) and the change preserves the size + alignment of all
  pre-existing fields.

### Patch bump (`0x00010000 -> 0x00010001`)

**Documentation or implementation fix that does not change the binary
contract.** Layout and signatures are byte-identical.

---

## 3. Migration guide

### Downstream C integrators

At library load time (immediately after `dlopen()` or before any other
`vs_*` call when statically linked):

```c
#include "cratonshield.h"

uint32_t actual_abi = vs_abi_version();
uint32_t expected_abi_major = VS_ABI_VERSION & 0xFFFF0000u;
uint32_t actual_abi_major   = actual_abi      & 0xFFFF0000u;

if (actual_abi_major != expected_abi_major) {
    /* Refuse to dispatch — the library was built against a different
     * major version than this header.  Recompile against the matching
     * cratonshield.h or downgrade libcratonshield. */
    log_fatal("ABI mismatch: expected %08x, got %08x",
              expected_abi_major, actual_abi_major);
    abort();
}
```

The same pattern applies to `vs-ffi-auto` with `vs_auto_abi_version()`
and `vs_auto.h`.

### Major-version migrations

When a major bump ships, this document will gain a `Migration: 1.x → 2.0`
section enumerating the breaking changes and the recommended port path.
Do not ship a major bump without that section.

---

## 4. ABI-stable vs reserved fields

### ABI-stable fields

Every field currently present in every `#[repr(C)]` struct exported from
the FFI crates is **ABI-stable**:

- `VsResult.code`
- All fields of `VsCanFrame` (`id`, `dlc`, `data[64]`, `is_extended`,
  `is_fd`, `timestamp_us`)
- All fields of `VsHealth` (and `VsHealthAuto` in the automotive crate)
- All fields of `VsCryptoCallbacks` (under the `production` feature),
  including the layout, ordering, and function-pointer signatures
- All fields of `VsEthPacket`, `VsLinFrame`, `VsFlexRayFrame`,
  `VsUdsRequest`, `VsUdsDecision`, `VsOtaManifest`

Changing any of the above requires a **major** bump.

### Reserved fields

Reserved fields are placeholders for future minor-bump additions. A
reserved field:

1. Has a name beginning with `_reserved` or is explicitly documented as
   "reserved for ABI use; initialize to zero".
2. Is documented as **MUST be zero** in current ABI versions.
3. May be repurposed in a future **minor** bump, provided that callers
   who initialized it to zero continue to receive correct behaviour.

At ABI 1.0 there are no fields explicitly carved out as reserved. The
`padding` byte in `VsEthPacket` is documented as "reserved padding byte
for ABI alignment" — repurposing it requires careful analysis and may
warrant a major bump.

---

## 5. Compile-time and runtime guards

Several layers of defense protect the contract:

1. **Rust-side compile-time assertions**
   - `const _: () = assert!(VS_ABI_VERSION == 0x00010000)` — keeps the
     Rust constant aligned with this document.
   - `const _: () = assert!(size_of::<VsCanFrame>() == 80)` and friends
     — pin struct sizes to fixed values.

2. **C-side compile-time assertions**
   - `_Static_assert(sizeof(VsCanFrame) == 80, ...)` in `cratonshield.h`
     — caught when a downstream consumer compiles against a mismatched
     header.

3. **Rust ABI regression tests** (`core/ffi/tests/abi.rs`)
   - Pin struct sizes and field offsets at the byte level.
   - Pin `VS_ABI_VERSION` and the return value of `vs_abi_version()`.

4. **Runtime guard for the consumer**
   - `vs_abi_version()` / `vs_auto_abi_version()` — the consumer's last
     line of defense against a library/header skew that escaped the
     above.

---

## 6. Process: making an ABI change

1. Open an issue describing the proposed change and which bump it
   triggers (major / minor / patch).
2. If major: write the `Migration: 1.x -> 2.0` section of this document
   in the same PR.
3. Bump the `VS_ABI_VERSION` constant in `cratonshield.h`,
   `vs_auto.h`, `core/ffi/src/lib.rs`, **and** `auto/ffi-auto/src/lib.rs`
   in one commit. The compile-time assertions will fail-fast if you
   miss one.
4. Update `core/ffi/tests/abi.rs` and any auto-side equivalents.
5. Update the per-crate README warning if the rationale changes.

---

## 7. Publication

Both `vs-ffi` and `vs-ffi-auto` are published to crates.io as part of
the workspace release. Cargo semver applies to the **Rust** API; the
**C** API is governed by this document.
