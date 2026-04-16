# Changelog

All notable changes to `vs-crypto` are documented in this file.

## [0.7.0]

### Breaking

- `RustCryptoPqProvider::default()` now produces an *unprovisioned*
  provider with `rng_installed = false`.  Any call to
  `set_mlkem_key(_, None)` / `set_mldsa_key(_, None)` or
  `mlkem_encapsulate` returns `VsError::NotInitialized` until an
  entropy source is installed via `RustCryptoPqProvider::install_rng`
  (or until the provider was constructed via `::new(rng)`).  This
  closes a zero-seed vulnerability where the previous no-op default
  RNG silently filled key seeds with zeros.  Explicit-seed
  `provision_mlkem_key` / `provision_mldsa_key` paths are unchanged.
- Removed the `NonceCounter::last_counter_value` accessor.  Use
  `counter_for_persistence()` instead — identical functionality with
  a clearer name.

### Changed

- `SeedRng::fill_bytes` no longer panics on seed exhaustion in
  release builds.  It now sets an internal `is_exhausted` flag,
  zero-fills the destination, and lets callers query the state via
  `SeedRng::is_exhausted()`.  Debug builds still panic so test runs
  surface caller bugs loudly.  `try_fill_bytes` continues to return
  `Err` on exhaustion without flipping the flag.

### Added

- `RustCryptoPqProvider::install_rng` for late RNG installation on
  a defaulted provider.
- `NonceTracker::check_only` for non-destructive nonce-reuse checks;
  used to avoid permanently consuming nonces when AEAD encrypt fails.
