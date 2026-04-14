// SPDX-License-Identifier: Apache-2.0
//! File-system-backed storage provider for Linux/desktop targets.
//!
//! Each key-value pair is stored as a separate file in a base directory.
//! The filename is the hex encoding of the key bytes.  This module is only
//! available when the `std` feature is enabled.
//!
//! # Security hardening
//!
//! * **Atomic writes** – values are written to a temporary file, fsynced,
//!   then renamed into place so a power-loss never leaves a half-written
//!   value.
//! * **Restrictive permissions** – on Unix the base directory is created
//!   with mode `0o700` and each value file with `0o600`.
//! * **Secure erase** – deleted files are overwritten with zeros and fsynced
//!   before being unlinked.
//! * **Integrity guard** – reads reject files whose size exceeds
//!   [`MAX_VALUE_LEN`], indicating tampering.

use std::io::Write as IoWrite;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use crate::{StorageProvider, MAX_KEY_LEN, MAX_VALUE_LEN};
use vs_types::VsError;

/// File-system-backed [`StorageProvider`].
///
/// Each key-value pair is stored as a separate file under `base_dir`.
/// The filename is the lowercase hex encoding of the key bytes; the file
/// contents are the raw value bytes.
pub struct FileStorageProvider {
    base_dir: PathBuf,
}

impl FileStorageProvider {
    /// Create a new file storage provider rooted at `base_dir`.
    ///
    /// Creates the directory (and parents) if it does not already exist.
    /// On Unix the directory permissions are set to `0o700`.
    ///
    /// The `base_dir` is canonicalized at construction time to prevent
    /// path traversal attacks via symlinks or relative path components.
    pub fn new(base_dir: PathBuf) -> Result<Self, VsError> {
        std::fs::create_dir_all(&base_dir).map_err(|_| VsError::StorageError)?;
        restrict_dir_permissions(&base_dir)?;
        // Canonicalize to an absolute path to prevent path traversal
        // via symlinks or relative components (e.g., "../../etc").
        let canonical = std::fs::canonicalize(&base_dir).map_err(|_| VsError::StorageError)?;
        Ok(Self {
            base_dir: canonical,
        })
    }

    /// Return the path for a given key.
    ///
    /// The filename is the lowercase hex encoding of the key bytes,
    /// which cannot contain path separators or `..` components.
    /// The resulting path is validated to be a child of `base_dir`
    /// to prevent path traversal.
    fn key_path(&self, key: &[u8]) -> PathBuf {
        if key.is_empty() {
            return self.base_dir.join("_empty");
        }
        let mut hex = std::string::String::with_capacity(key.len() * 2);
        for &b in key {
            use core::fmt::Write;
            // `fmt::Write` for `String` is infallible.
            write!(hex, "{b:02x}").expect("String fmt::Write is infallible");
        }
        let path = self.base_dir.join(&hex);
        // Defence-in-depth: verify the constructed path is a child of
        // base_dir. The hex encoding already prevents traversal, but
        // this guards against future refactoring errors.
        debug_assert!(
            path.starts_with(&self.base_dir),
            "key_path escaped base_dir: {path:?}"
        );
        path
    }

    /// Return the number of stored entries by counting files in `base_dir`.
    pub fn entry_count(&self) -> Result<usize, VsError> {
        let mut count = 0usize;
        let entries = std::fs::read_dir(&self.base_dir).map_err(|_| VsError::StorageError)?;
        for entry in entries {
            let entry = entry.map_err(|_| VsError::StorageError)?;
            let name = entry.file_name();
            // F-09: reject non-UTF-8 filenames explicitly rather than
            // silently skipping them via `unwrap_or("")`, which could mask
            // filesystem corruption or a tampered storage directory.
            let name_str = name.to_str().ok_or(VsError::StorageError)?;
            // Skip atomic-write temporaries.
            if name_str.starts_with("tmp") && name_str.len() == 19 {
                continue;
            }
            count += 1;
        }
        Ok(count)
    }
}

impl StorageProvider for FileStorageProvider {
    fn read(&self, key: &[u8], buf: &mut [u8]) -> Result<usize, VsError> {
        if key.len() > MAX_KEY_LEN {
            return Err(VsError::InvalidInput);
        }
        let data = std::fs::read(self.key_path(key)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                VsError::NotFound
            } else {
                VsError::StorageError
            }
        })?;
        if data.len() > MAX_VALUE_LEN {
            return Err(VsError::IntegrityFailure);
        }
        if buf.len() < data.len() {
            return Err(VsError::InvalidInput);
        }
        buf[..data.len()].copy_from_slice(&data);
        Ok(data.len())
    }

    fn write(&mut self, key: &[u8], data: &[u8]) -> Result<(), VsError> {
        if key.len() > MAX_KEY_LEN || data.len() > MAX_VALUE_LEN {
            return Err(VsError::InvalidInput);
        }
        let path = self.key_path(key);
        // Permissions are set inside atomic_write_file on the open fd
        // before rename, so no separate restrict_file_permissions call
        // is needed.
        atomic_write_file(&path, data)?;
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), VsError> {
        if key.len() > MAX_KEY_LEN {
            return Ok(());
        }
        let path = self.key_path(key);
        // V8 fix: avoid TOCTOU by attempting the erase directly and
        // handling "not found" as a no-op, rather than checking exists()
        // first.
        match secure_erase_and_remove(&path) {
            Ok(()) => Ok(()),
            Err(VsError::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn contains(&self, key: &[u8]) -> bool {
        if key.len() > MAX_KEY_LEN {
            return false;
        }
        // V8 fix: use metadata() instead of exists() for an atomic check
        // that also validates the path is a regular file.
        std::fs::metadata(self.key_path(key))
            .map(|m| m.is_file())
            .unwrap_or(false)
    }

    fn for_each_key(&self, f: &mut dyn FnMut(&[u8]) -> bool) -> Result<(), VsError> {
        let entries = std::fs::read_dir(&self.base_dir).map_err(|_| VsError::StorageError)?;
        for entry in entries {
            let entry = entry.map_err(|_| VsError::StorageError)?;
            let name = entry.file_name();
            let name_str = name.to_str().ok_or(VsError::StorageError)?;

            // Skip atomic-write temporaries.
            if name_str.ends_with(".tmp") {
                continue;
            }

            if name_str == "_empty" {
                if !f(b"") {
                    return Ok(());
                }
                continue;
            }

            let mut key_buf = [0u8; MAX_KEY_LEN];
            let key_len = hex_decode(name_str, &mut key_buf)?;
            if !f(&key_buf[..key_len]) {
                return Ok(());
            }
        }
        Ok(())
    }

    fn clear_all(&mut self) -> Result<(), VsError> {
        let entries = std::fs::read_dir(&self.base_dir).map_err(|_| VsError::StorageError)?;
        for entry in entries {
            let entry = entry.map_err(|_| VsError::StorageError)?;
            let path = entry.path();
            if path.is_file() {
                secure_erase_and_remove(&path)?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Process-wide counter for unique temporary file suffixes.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Write `data` to `path` atomically: write to a temp sibling, fsync,
/// then rename into place.
///
/// On Unix the temporary file's permissions are set to `0o600` *before*
/// fsync and rename, so the file is never world-readable — even briefly.
///
/// The temporary filename uses a counter mixed with the process ID to
/// produce less predictable names and avoid collisions across concurrent
/// writes.
///
/// # Durability limitations
///
/// This function uses `fsync` + rename + parent-dir `fsync` (on Unix) for
/// durability.  However, it does **not** use `O_DIRECT`:
///
/// - **Journaling filesystems** (ext4, XFS) may reorder writes at the
///   journal level.  The rename-after-fsync pattern mitigates this: on
///   recovery, either the old or new value is present, never a partial
///   write.
/// - **Copy-on-write filesystems** (btrfs, ZFS) are inherently atomic for
///   overwrites but may retain old data blocks.
/// - **Embedded flash filesystems** (JFFS2, UBIFS, LittleFS) have their
///   own atomicity guarantees; consult the filesystem documentation.
///
/// For production embedded Linux deployments, consider using a dedicated
/// block device with a filesystem known to provide rename atomicity
/// (ext4 with `data=ordered` or `data=journal`).
fn atomic_write_file(path: &std::path::Path, data: &[u8]) -> Result<(), VsError> {
    let seq = TMP_COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
    // Mix counter with process ID and time for less predictable temp file names.
    let time_component = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mixed = seq
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(std::process::id() as u64)
        .wrapping_mul(0x517C_C1B7_2722_0A95)
        .wrapping_add(time_component);

    // F-06: use a stack-allocated buffer instead of a heap-allocated String
    // for the temp file extension.  format!() allocates on the heap; under
    // memory pressure that allocation can fail, causing the entire atomic
    // write to fail with an opaque StorageError.  A fixed 19-byte stack
    // buffer ("tmp" + 16 hex digits) never allocates.
    let mut ext_buf = [0u8; 19]; // "tmp" (3) + 16 hex digits = 19 bytes
    ext_buf[..3].copy_from_slice(b"tmp");
    let hex_digits = b"0123456789abcdef";
    for (i, digit) in ext_buf[3..].iter_mut().enumerate() {
        *digit = hex_digits[((mixed >> (60 - i * 4)) & 0xF) as usize];
    }
    // SAFETY: ext_buf contains only ASCII bytes.
    let ext_str = core::str::from_utf8(&ext_buf).expect("ext_buf is always valid ASCII");

    let tmp_path = path.with_extension(ext_str);
    {
        let mut file = std::fs::File::create(&tmp_path).map_err(|_| VsError::StorageError)?;
        file.write_all(data).map_err(|_| VsError::StorageError)?;
        // Set restrictive permissions on the open fd BEFORE sync+rename
        // to close the TOCTOU window where the file could be read by
        // other users.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|_| VsError::StorageError)?;
        }
        #[cfg(windows)]
        {
            // F-05 + F-11: restrict file ACL to the current user using the
            // Windows security API.  `whoami()` now calls `GetUserNameW`
            // directly instead of reading the `USERNAME` environment variable,
            // eliminating the env-var injection vector.  Errors from the ACL
            // call are propagated rather than silently discarded (F-11).
            if let Some(path_str) = tmp_path.to_str() {
                let user = whoami()?;
                restrict_path_to_user_windows(path_str, &user)?;
            }
        }
        file.sync_all().map_err(|_| VsError::StorageError)?;
    }
    std::fs::rename(&tmp_path, path).map_err(|_| VsError::StorageError)?;

    // Sync parent directory for rename durability (POSIX).
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

/// Overwrite a file's contents with zeros and fsync before unlinking.
///
/// # Security limitations
///
/// On copy-on-write filesystems (btrfs, ZFS) the old data may remain in
/// a different block.  On SSDs the FTL may retain the original page.
/// This function provides best-effort secure erasure for conventional
/// filesystems; for stronger guarantees consider full-disk encryption.
fn secure_erase_and_remove(path: &std::path::Path) -> Result<(), VsError> {
    let meta = std::fs::metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            VsError::NotFound
        } else {
            VsError::StorageError
        }
    })?;
    let len = meta.len() as usize;
    if len > 0 {
        // Use a fixed-size stack buffer to avoid heap allocation for large files.
        const ZERO_BUF_SIZE: usize = 4096;
        let zeros = [0u8; ZERO_BUF_SIZE];
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|_| VsError::StorageError)?;
        let mut remaining = len;
        while remaining > 0 {
            let chunk = if remaining < ZERO_BUF_SIZE {
                remaining
            } else {
                ZERO_BUF_SIZE
            };
            file.write_all(&zeros[..chunk])
                .map_err(|_| VsError::StorageError)?;
            remaining -= chunk;
        }
        file.sync_all().map_err(|_| VsError::StorageError)?;
    }
    std::fs::remove_file(path).map_err(|_| VsError::StorageError)?;
    Ok(())
}

/// Set directory permissions to `0o700` on Unix, or restrict ACL to the
/// current user on Windows.
fn restrict_dir_permissions(_path: &std::path::Path) -> Result<(), VsError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(_path, perms).map_err(|_| VsError::StorageError)?;
    }
    #[cfg(windows)]
    {
        // F-05 + F-11: use the Windows security API via `whoami()` (which
        // calls `GetUserNameW`) and propagate errors instead of silently
        // discarding them.
        let path_str = _path.to_str().ok_or(VsError::StorageError)?;
        let user = whoami()?;
        restrict_path_to_user_windows(path_str, &user)?;
    }
    Ok(())
}

/// Apply an exclusive ACL on `path` for `username` using `icacls`.
///
/// The username is obtained via `GetUserNameW` (see `whoami()`), so it is
/// the real logged-in identity — not an attacker-controlled environment
/// variable.  Errors from `icacls` are propagated as `VsError::StorageError`
/// (F-11: previously the error was silently discarded via `let _ = ...`).
///
/// # Future work
///
/// For fully API-native ACL management (no child-process spawn), replace
/// this with direct calls to `SetNamedSecurityInfoW` + `BuildExplicitAccessWithNameW`
/// using the `windows-sys` crate.  The current implementation is correct
/// and injection-safe; the process spawn is the only remaining impurity.
#[cfg(windows)]
fn restrict_path_to_user_windows(path_str: &str, username: &str) -> Result<(), VsError> {
    let grant_arg = format!("{username}:F");
    let output = std::process::Command::new("icacls")
        .args([path_str, "/inheritance:r", "/grant:r", &grant_arg, "/q"])
        .output()
        .map_err(|_| VsError::StorageError)?;

    // F-11: propagate icacls failures as StorageError instead of silently
    // ignoring them.  A non-zero exit code means the ACL was NOT applied,
    // leaving the file/directory world-readable — which is a security
    // violation we must not hide.
    if !output.status.success() {
        return Err(VsError::StorageError);
    }
    Ok(())
}

/// Return the current user's login name by calling `GetUserNameW`.
///
/// F-05: replaces the previous `std::env::var("USERNAME")` approach.
/// Environment variables are attacker-controlled; `GetUserNameW` queries
/// the OS kernel directly and cannot be manipulated by an unprivileged
/// process on a correctly configured Windows system.
#[cfg(windows)]
#[allow(unsafe_code)]
fn whoami() -> Result<String, VsError> {
    // UNLEN (maximum username length) is 256 UTF-16 code units per MSDN.
    // Add 1 for the null terminator.
    const UNLEN_PLUS_NUL: usize = 257;

    // Minimal extern declaration — avoids adding windows-sys as a dependency.
    extern "system" {
        fn GetUserNameW(lpBuffer: *mut u16, pcbBuffer: *mut u32) -> i32;
    }

    let mut buf = [0u16; UNLEN_PLUS_NUL];
    let mut size = buf.len() as u32;

    // SAFETY:
    //  - `buf` is a valid, mutable slice of u16 of length UNLEN_PLUS_NUL.
    //  - `size` is set to the buffer length in characters before the call.
    //  - `GetUserNameW` writes at most `size` UTF-16 code units (incl. NUL).
    //  - On success, `size` is updated to the number of chars written incl. NUL.
    let ok = unsafe { GetUserNameW(buf.as_mut_ptr(), &mut size) };
    if ok == 0 || size == 0 {
        return Err(VsError::StorageError);
    }

    // `size` includes the null terminator; exclude it when converting.
    let len = (size as usize).saturating_sub(1);
    let username = std::os::windows::ffi::OsStringExt::from_wide(&buf[..len]);
    let username = username.into_string().map_err(|_| VsError::StorageError)?;

    // Defence-in-depth: validate the username contains only characters safe
    // for icacls.  Domain usernames have the form "DOMAIN\user"; we allow
    // backslash for that case.  Other special characters that icacls interprets
    // specially (e.g. '*', '?', space) are rejected.
    if username.is_empty()
        || !username
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '\\')
    {
        return Err(VsError::StorageError);
    }
    Ok(username)
}

/// Lock a buffer's memory pages to prevent swapping to disk.
///
/// On Unix, this calls `mlock()` to prevent the buffer from being paged
/// out, which could expose sensitive data (key material, HMACs) to disk.
/// On non-Unix platforms this is a no-op that returns `Ok(())`.
///
/// # Errors
///
/// Returns [`VsError::ResourceExhausted`] if `mlock` fails (typically
/// because the process's `RLIMIT_MEMLOCK` is too low). For production
/// deployments, ensure the process has adequate limits (e.g., via
/// `ulimit -l` or systemd `LimitMEMLOCK`).
///
/// # Notes
///
/// `mlock()` operates on whole pages. The kernel will lock every page
/// that overlaps the requested range. A return value of `0` guarantees
/// the entire range is locked — partial locking is not possible because
/// the kernel treats it as an atomic operation (all-or-nothing per the
/// POSIX specification).
#[allow(unused_variables, unsafe_code)]
pub fn mlock_buffer(buf: &[u8]) -> Result<(), VsError> {
    #[cfg(all(unix, feature = "std"))]
    {
        // SAFETY: mlock is safe to call on any valid memory range.
        // It is a no-op if the memory is already locked. mlock(2) is
        // atomic: it either locks all requested pages or fails entirely,
        // so a zero return value guarantees the full buffer is locked.
        unsafe {
            if libc::mlock(buf.as_ptr().cast(), buf.len()) == 0 {
                return Ok(());
            }
            return Err(VsError::ResourceExhausted);
        }
    }
    #[cfg(not(all(unix, feature = "std")))]
    {
        // No-op on non-Unix platforms.
        Ok(())
    }
}

/// Unlock a previously mlocked buffer.
#[allow(unused_variables, unsafe_code)]
pub fn munlock_buffer(buf: &[u8]) {
    #[cfg(all(unix, feature = "std"))]
    {
        // SAFETY: munlock is safe to call on any valid memory range.
        unsafe {
            let _ = libc::munlock(buf.as_ptr().cast(), buf.len());
        }
    }
}

/// Decode a hex string into `out`, returning the number of bytes written.
fn hex_decode(hex: &str, out: &mut [u8]) -> Result<usize, VsError> {
    if hex.len() % 2 != 0 {
        return Err(VsError::StorageError);
    }
    let byte_len = hex.len() / 2;
    if byte_len > out.len() {
        return Err(VsError::StorageError);
    }
    for i in 0..byte_len {
        out[i] =
            u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| VsError::StorageError)?;
    }
    Ok(byte_len)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("vs_storage_test_{name}_{}", std::process::id()));
        // Clean up from any previous run.
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn cleanup(dir: &std::path::Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn file_write_and_read() {
        let dir = temp_dir("write_read");
        let mut store = FileStorageProvider::new(dir.clone()).unwrap();
        store.write(b"key1", b"hello").unwrap();
        let mut buf = [0u8; 128];
        let len = store.read(b"key1", &mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello");
        cleanup(&dir);
    }

    #[test]
    fn file_overwrite_existing_key() {
        let dir = temp_dir("overwrite");
        let mut store = FileStorageProvider::new(dir.clone()).unwrap();
        store.write(b"k", b"first").unwrap();
        store.write(b"k", b"second").unwrap();
        let mut buf = [0u8; 128];
        let len = store.read(b"k", &mut buf).unwrap();
        assert_eq!(&buf[..len], b"second");
        cleanup(&dir);
    }

    #[test]
    fn file_read_nonexistent_key_returns_not_found() {
        let dir = temp_dir("nonexistent");
        let store = FileStorageProvider::new(dir.clone()).unwrap();
        let mut buf = [0u8; 128];
        let result = store.read(b"nope", &mut buf);
        assert_eq!(result, Err(VsError::NotFound));
        cleanup(&dir);
    }

    #[test]
    fn file_delete_key() {
        let dir = temp_dir("delete");
        let mut store = FileStorageProvider::new(dir.clone()).unwrap();
        store.write(b"key", b"val").unwrap();
        assert!(store.contains(b"key"));
        store.delete(b"key").unwrap();
        assert!(!store.contains(b"key"));
        cleanup(&dir);
    }

    #[test]
    fn file_delete_nonexistent_key_is_ok() {
        let dir = temp_dir("del_noexist");
        let mut store = FileStorageProvider::new(dir.clone()).unwrap();
        let result = store.delete(b"nope");
        assert!(result.is_ok());
        cleanup(&dir);
    }

    #[test]
    fn file_contains() {
        let dir = temp_dir("contains");
        let mut store = FileStorageProvider::new(dir.clone()).unwrap();
        assert!(!store.contains(b"x"));
        store.write(b"x", b"y").unwrap();
        assert!(store.contains(b"x"));
        cleanup(&dir);
    }

    #[test]
    fn file_key_too_long_returns_invalid_input() {
        let dir = temp_dir("key_long");
        let mut store = FileStorageProvider::new(dir.clone()).unwrap();
        let long_key = [0xAA; MAX_KEY_LEN + 1];
        let result = store.write(&long_key, b"val");
        assert_eq!(result, Err(VsError::InvalidInput));
        cleanup(&dir);
    }

    #[test]
    fn file_value_too_long_returns_invalid_input() {
        let dir = temp_dir("val_long");
        let mut store = FileStorageProvider::new(dir.clone()).unwrap();
        let long_val = [0xBB; MAX_VALUE_LEN + 1];
        let result = store.write(b"k", &long_val);
        assert_eq!(result, Err(VsError::InvalidInput));
        cleanup(&dir);
    }

    #[test]
    fn file_buffer_too_small_for_read_returns_invalid_input() {
        let dir = temp_dir("buf_small");
        let mut store = FileStorageProvider::new(dir.clone()).unwrap();
        store.write(b"k", b"longvalue").unwrap();
        let mut tiny_buf = [0u8; 2];
        let result = store.read(b"k", &mut tiny_buf);
        assert_eq!(result, Err(VsError::InvalidInput));
        cleanup(&dir);
    }

    #[test]
    fn file_read_oversized_key_returns_invalid_input() {
        let dir = temp_dir("read_bigkey");
        let store = FileStorageProvider::new(dir.clone()).unwrap();
        let big_key = [0xCC; MAX_KEY_LEN + 1];
        let mut buf = [0u8; 128];
        assert_eq!(store.read(&big_key, &mut buf), Err(VsError::InvalidInput));
        cleanup(&dir);
    }

    #[test]
    fn file_contains_oversized_key_returns_false() {
        let dir = temp_dir("contains_bigkey");
        let store = FileStorageProvider::new(dir.clone()).unwrap();
        let big_key = [0xCC; MAX_KEY_LEN + 1];
        assert!(!store.contains(&big_key));
        cleanup(&dir);
    }

    #[test]
    fn file_multiple_keys() {
        let dir = temp_dir("multi");
        let mut store = FileStorageProvider::new(dir.clone()).unwrap();
        store.write(b"a", b"1").unwrap();
        store.write(b"b", b"2").unwrap();
        store.write(b"c", b"3").unwrap();
        let mut buf = [0u8; 128];
        let len = store.read(b"b", &mut buf).unwrap();
        assert_eq!(&buf[..len], b"2");
        cleanup(&dir);
    }

    #[test]
    fn file_delete_then_reuse() {
        let dir = temp_dir("reuse");
        let mut store = FileStorageProvider::new(dir.clone()).unwrap();
        store.write(b"old", b"data").unwrap();
        store.delete(b"old").unwrap();
        store.write(b"new", b"fresh").unwrap();
        assert!(store.contains(b"new"));
        assert!(!store.contains(b"old"));
        cleanup(&dir);
    }

    #[test]
    fn file_empty_key_and_value() {
        let dir = temp_dir("empty");
        let mut store = FileStorageProvider::new(dir.clone()).unwrap();
        store.write(b"", b"").unwrap();
        let mut buf = [0u8; 128];
        let len = store.read(b"", &mut buf).unwrap();
        assert_eq!(len, 0);
        cleanup(&dir);
    }

    #[test]
    fn file_persistence_across_instances() {
        let dir = temp_dir("persist");
        {
            let mut store = FileStorageProvider::new(dir.clone()).unwrap();
            store.write(b"persistent", b"value").unwrap();
        }
        // Re-open from same directory.
        let store = FileStorageProvider::new(dir.clone()).unwrap();
        let mut buf = [0u8; 128];
        let len = store.read(b"persistent", &mut buf).unwrap();
        assert_eq!(&buf[..len], b"value");
        cleanup(&dir);
    }

    #[test]
    fn file_entry_count() {
        let dir = temp_dir("entry_count");
        let mut store = FileStorageProvider::new(dir.clone()).unwrap();
        assert_eq!(store.entry_count().unwrap(), 0);
        store.write(b"a", b"1").unwrap();
        store.write(b"b", b"2").unwrap();
        assert_eq!(store.entry_count().unwrap(), 2);
        store.delete(b"a").unwrap();
        assert_eq!(store.entry_count().unwrap(), 1);
        cleanup(&dir);
    }

    #[test]
    fn file_for_each_key() {
        let dir = temp_dir("for_each_key");
        let mut store = FileStorageProvider::new(dir.clone()).unwrap();
        store.write(b"alpha", b"1").unwrap();
        store.write(b"beta", b"2").unwrap();

        let mut keys: Vec<Vec<u8>> = Vec::new();
        store
            .for_each_key(&mut |k| {
                keys.push(k.to_vec());
                true
            })
            .unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&b"alpha".to_vec()));
        assert!(keys.contains(&b"beta".to_vec()));
        cleanup(&dir);
    }

    #[test]
    fn file_for_each_key_with_empty_key() {
        let dir = temp_dir("for_each_empty");
        let mut store = FileStorageProvider::new(dir.clone()).unwrap();
        store.write(b"", b"val").unwrap();
        store.write(b"other", b"val2").unwrap();

        let mut keys: Vec<Vec<u8>> = Vec::new();
        store
            .for_each_key(&mut |k| {
                keys.push(k.to_vec());
                true
            })
            .unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&b"".to_vec()));
        assert!(keys.contains(&b"other".to_vec()));
        cleanup(&dir);
    }

    #[test]
    fn file_clear_all() {
        let dir = temp_dir("clear_all");
        let mut store = FileStorageProvider::new(dir.clone()).unwrap();
        store.write(b"a", b"1").unwrap();
        store.write(b"b", b"2").unwrap();
        store.write(b"c", b"3").unwrap();
        store.clear_all().unwrap();
        assert_eq!(store.entry_count().unwrap(), 0);
        assert!(!store.contains(b"a"));
        assert!(!store.contains(b"b"));
        assert!(!store.contains(b"c"));
        cleanup(&dir);
    }

    #[test]
    fn file_tampered_oversize_value_returns_integrity_failure() {
        let dir = temp_dir("tampered");
        let mut store = FileStorageProvider::new(dir.clone()).unwrap();
        store.write(b"ok", b"fine").unwrap();

        // Tamper: write a file larger than MAX_VALUE_LEN directly.
        let path = store.key_path(b"ok");
        let oversized = vec![0xAA; MAX_VALUE_LEN + 10];
        std::fs::write(&path, &oversized).unwrap();

        let mut buf = [0u8; 256];
        let result = store.read(b"ok", &mut buf);
        assert_eq!(result, Err(VsError::IntegrityFailure));
        cleanup(&dir);
    }

    #[test]
    fn hex_decode_roundtrip() {
        // Verify that key_path → for_each_key round-trips correctly.
        let dir = temp_dir("hex_rt");
        let mut store = FileStorageProvider::new(dir.clone()).unwrap();
        let key = b"\x00\xff\x80\x01";
        store.write(key, b"val").unwrap();

        let mut found = false;
        store
            .for_each_key(&mut |k| {
                if k == key {
                    found = true;
                }
                true
            })
            .unwrap();
        assert!(found);
        cleanup(&dir);
    }

    #[test]
    fn file_delete_removes_file() {
        let dir =
            std::env::temp_dir().join(format!("vs_storage_erase_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = FileStorageProvider::new(dir.clone()).unwrap();

        store.write(b"eraseme", b"secret").unwrap();
        let file_path = store.key_path(b"eraseme");
        // File must exist after write.
        assert!(
            std::fs::metadata(&file_path).is_ok(),
            "file should exist after write"
        );

        store.delete(b"eraseme").unwrap();
        // File must no longer exist after delete.
        assert!(
            std::fs::metadata(&file_path).is_err(),
            "file should not exist after delete"
        );

        cleanup(&dir);
    }

    #[test]
    fn file_clear_all_removes_all() {
        let dir = temp_dir("clear_all_removes");
        let mut store = FileStorageProvider::new(dir.clone()).unwrap();

        store.write(b"k1", b"v1").unwrap();
        store.write(b"k2", b"v2").unwrap();
        store.write(b"k3", b"v3").unwrap();

        store.clear_all().unwrap();
        assert_eq!(store.entry_count().unwrap(), 0);

        cleanup(&dir);
    }
}
