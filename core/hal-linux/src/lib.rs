// SPDX-License-Identifier: Apache-2.0
#![allow(unsafe_code)]
//! Linux userspace HAL implementations for `Craton Shield`.
//!
//! Provides `LinuxCanBus` (via `SocketCAN`),
//! `LinuxTimer` (via `clock_gettime`), and
//! `LinuxEthernetPhy` (via `AF_PACKET` raw
//! sockets).
//!
//! These implementations target NXP S32G3 and other Linux-based automotive
//! platforms. On non-Linux targets this crate is empty.

#[cfg(target_os = "linux")]
mod can;
#[cfg(target_os = "linux")]
mod ethernet;
#[cfg(target_os = "linux")]
mod timer;

#[cfg(target_os = "linux")]
pub use can::{CanFilter, LinuxCanBus};
#[cfg(target_os = "linux")]
pub use ethernet::LinuxEthernetPhy;
#[cfg(target_os = "linux")]
pub use timer::LinuxTimer;

/// Convert a negative libc return value (with `errno` set) into a [`VsError`].
#[cfg(target_os = "linux")]
fn errno_to_vserror() -> vs_types::VsError {
    // SAFETY: reading errno via the thread-local __errno_location pointer.
    let e = unsafe { *libc::__errno_location() };
    match e {
        libc::EAGAIN => vs_types::VsError::Timeout,
        libc::ENODEV | libc::ENXIO | libc::ENETDOWN => vs_types::VsError::BusError,
        libc::ENOMEM | libc::ENOBUFS => vs_types::VsError::ResourceExhausted,
        libc::EINVAL => vs_types::VsError::InvalidInput,
        // EACCES/EPERM are OS permission errors — map to BusError because
        // VsError has no PermissionDenied variant and these typically mean
        // the process lacks CAP_NET_RAW or the interface is inaccessible.
        libc::EACCES | libc::EPERM => vs_types::VsError::BusError,
        _ => vs_types::VsError::BusError,
    }
}
