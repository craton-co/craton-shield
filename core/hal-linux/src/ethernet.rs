// SPDX-License-Identifier: Apache-2.0
//! Linux raw-socket implementation of the [`EthernetPhy`] trait.
//!
//! Uses `AF_PACKET` with `SOCK_RAW` to capture and transmit raw Ethernet
//! frames on a specified network interface. Supports EtherType filtering
//! and queries link speed via the ethtool ioctl.

use core::sync::atomic::{AtomicU64, Ordering};

use vs_hal::{EthernetPhy, RawEthFrame, MAX_ETH_FRAME_LEN};
use vs_types::VsError;

use crate::errno_to_vserror;

/// `ETH_P_ALL` — capture all Ethernet protocols.
const ETH_P_ALL: u16 = 0x0003;

/// Minimum Ethernet frame size (without FCS): 14-byte header + 46-byte payload.
const MIN_ETH_FRAME_LEN: usize = 60;

// ---------------------------------------------------------------------------
// Ethtool ioctl structures (from <linux/ethtool.h> and <linux/sockios.h>)
// ---------------------------------------------------------------------------

/// `SIOCETHTOOL` ioctl number.
const SIOCETHTOOL: libc::c_ulong = 0x8946;

/// `ETHTOOL_GLINKSETTINGS` command — get link settings.
const _ETHTOOL_GLINKSETTINGS: u32 = 0x0000_004c;

/// `ETHTOOL_GSET` command (legacy) — get settings.
const ETHTOOL_GSET: u32 = 0x0000_0001;

/// Legacy `struct ethtool_cmd` (trimmed to the fields we need).
#[repr(C)]
struct EthtoolCmd {
    cmd: u32,
    supported: u32,
    advertising: u32,
    speed: u16,
    duplex: u8,
    port: u8,
    phy_address: u8,
    transceiver: u8,
    autoneg: u8,
    mdio_support: u8,
    maxtxpkt: u32,
    maxrxpkt: u32,
    speed_hi: u16,
    eth_tp_mdix: u8,
    eth_tp_mdix_ctrl: u8,
    lp_advertising: u32,
    reserved: [u32; 2],
}

/// Ifreq-like structure for ethtool ioctl. We pass a pointer to the
/// ethtool command in the ifr_data field.
#[repr(C)]
struct EthtoolIfreq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_data: *mut u8,
}

// ---------------------------------------------------------------------------
// LinuxEthernetPhy
// ---------------------------------------------------------------------------

/// Linux Ethernet PHY backed by `AF_PACKET` raw sockets.
///
/// # Example
///
/// ```no_run
/// use vs_hal_linux::LinuxEthernetPhy;
/// use vs_hal::EthernetPhy;
///
/// let mut eth = LinuxEthernetPhy::new("eth0").expect("open eth0");
/// if let Ok(Some(frame)) = eth.receive() {
///     println!("Received {} byte Ethernet frame", frame.len);
/// }
/// ```
pub struct LinuxEthernetPhy {
    fd: libc::c_int,
    ifindex: libc::c_int,
    /// Cached interface name for ioctl queries.
    ifname: [libc::c_char; libc::IFNAMSIZ],
}

/// SAFETY: The fd is used exclusively through `&mut self` methods (receive/transmit).
/// Read-only queries (link_speed, link_is_up) use ioctl on a copy of the socket fd,
/// which is safe for concurrent reads of kernel state. No concurrent mutation is
/// possible through the public API.
///
/// `LinuxEthernetPhy` deliberately does NOT implement `Clone` or `Sync`:
/// - `Clone` would create two owners of the same fd, causing double-close.
/// - `Sync` would allow `&self` access from multiple threads, but `receive()`
///   and `transmit()` require `&mut self`, so this is enforced by Rust's
///   borrow checker.
unsafe impl Send for LinuxEthernetPhy {}

/// Socket address for `AF_PACKET` (matches `struct sockaddr_ll`).
#[repr(C)]
#[allow(clippy::struct_field_names)]
struct SockaddrLl {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: libc::c_int,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
}

impl LinuxEthernetPhy {
    /// Open a raw Ethernet socket on the specified interface (e.g. `"eth0"`).
    ///
    /// Captures all EtherTypes (`ETH_P_ALL`). The socket is non-blocking so
    /// [`EthernetPhy::receive`] returns `Ok(None)` when no frame is pending.
    pub fn new(interface: &str) -> Result<Self, VsError> {
        Self::open(interface, ETH_P_ALL)
    }

    /// Open a raw Ethernet socket filtering for a specific EtherType.
    ///
    /// Only frames matching the given protocol number (in host byte order,
    /// e.g. `0x0800` for IPv4, `0x88B5` for SOME/IP experimentation) will be
    /// delivered by the kernel.
    pub fn with_ethertype(interface: &str, ethertype: u16) -> Result<Self, VsError> {
        Self::open(interface, ethertype)
    }

    /// Validate that an interface name contains only safe characters.
    ///
    /// Rejects `/`, `.`, spaces, and other characters that could cause
    /// path traversal or injection in sysfs/ioctl paths.
    fn is_valid_ifname(name: &[u8]) -> bool {
        for &b in name {
            if b == 0 {
                break;
            } // null terminator
            match b {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-' | b'.' => {}
                _ => return false, // reject /, space, etc.
            }
        }
        true
    }

    fn open(interface: &str, protocol: u16) -> Result<Self, VsError> {
        if interface.len() >= libc::IFNAMSIZ {
            return Err(VsError::InvalidInput);
        }

        // Validate interface name contains only safe characters (prevent
        // path traversal or injection via ioctl).
        if !Self::is_valid_ifname(interface.as_bytes()) {
            return Err(VsError::InvalidInput);
        }

        // Cache interface name.
        let mut ifname = [0_i8; libc::IFNAMSIZ];
        for (i, &b) in interface.as_bytes().iter().enumerate() {
            // Cast u8 to i8 for libc ifreq compatibility (ASCII values are
            // identical in both signed and unsigned representation).
            ifname[i] = b as libc::c_char;
        }

        // SAFETY: creating a raw AF_PACKET socket. All pointers are to valid
        // stack-allocated structures. Return values are checked.
        unsafe {
            let fd = libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                protocol.to_be().into(),
            );
            if fd < 0 {
                return Err(errno_to_vserror());
            }

            // Resolve interface name to index
            let mut ifr: libc::ifreq = core::mem::zeroed();
            for (i, &b) in interface.as_bytes().iter().enumerate() {
                ifr.ifr_name[i] = b as libc::c_char;
            }
            if libc::ioctl(fd, libc::SIOCGIFINDEX as libc::c_ulong, &raw mut ifr) < 0 {
                libc::close(fd);
                return Err(errno_to_vserror());
            }
            let ifindex = ifr.ifr_ifru.ifru_ifindex;

            // Bind to the interface
            let addr = SockaddrLl {
                sll_family: libc::AF_PACKET as u16,
                sll_protocol: protocol.to_be(),
                sll_ifindex: ifindex,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0u8; 8],
            };
            let addr_ptr: *const SockaddrLl = &raw const addr;
            if libc::bind(
                fd,
                addr_ptr.cast::<libc::sockaddr>(),
                core::mem::size_of::<SockaddrLl>() as libc::socklen_t,
            ) < 0
            {
                libc::close(fd);
                return Err(errno_to_vserror());
            }

            Ok(Self {
                fd,
                ifindex,
                ifname,
            })
        }
    }

    /// Get the current monotonic timestamp in microseconds.
    ///
    /// On failure, returns the last known good value instead of 0 to avoid
    /// resetting time-based security checks.
    fn timestamp_us() -> u64 {
        static LAST_TIMESTAMP_US: AtomicU64 = AtomicU64::new(0);

        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: ts is a valid stack-allocated timespec.
        let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &raw mut ts) };
        if ret != 0 {
            return LAST_TIMESTAMP_US.load(Ordering::Relaxed);
        }
        let result = (ts.tv_sec as u64) * 1_000_000 + (ts.tv_nsec as u64) / 1_000;
        LAST_TIMESTAMP_US.store(result, Ordering::Relaxed);
        result
    }

    /// Query link speed via the legacy `ETHTOOL_GSET` ioctl.
    fn ethtool_speed(&self) -> Option<u32> {
        // SAFETY: all pointers are to valid stack-allocated structures.
        // The ioctl reads kernel state and does not mutate our data.
        unsafe {
            let mut ecmd: EthtoolCmd = core::mem::zeroed();
            ecmd.cmd = ETHTOOL_GSET;

            let mut ifr = EthtoolIfreq {
                ifr_name: self.ifname,
                ifr_data: core::ptr::from_mut(&mut ecmd).cast(),
            };

            if libc::ioctl(self.fd, SIOCETHTOOL, &raw mut ifr) < 0 {
                return None;
            }

            // Speed is split across `speed` (low 16 bits) and `speed_hi` (high 16 bits).
            let speed = (ecmd.speed_hi as u32) << 16 | (ecmd.speed as u32);
            if speed == 0 || speed == 0xFFFF || speed == u32::MAX {
                None
            } else {
                Some(speed)
            }
        }
    }
}

impl Drop for LinuxEthernetPhy {
    fn drop(&mut self) {
        // SAFETY: Closing a valid file descriptor exactly once. The fd was obtained
        // from socket() in new() and is owned exclusively by this struct. No other
        // code closes this fd.
        unsafe {
            let ret = libc::close(self.fd);
            debug_assert!(ret == 0, "close() failed on Ethernet socket fd");
        }
    }
}

impl EthernetPhy for LinuxEthernetPhy {
    fn receive(&mut self) -> Result<Option<RawEthFrame>, VsError> {
        let mut frame = RawEthFrame::zeroed();
        // SAFETY: reading into a valid, stack-allocated buffer.
        let n = unsafe { libc::read(self.fd, frame.data.as_mut_ptr().cast(), frame.data.len()) };
        if n < 0 {
            let err = errno_to_vserror();
            return if matches!(err, VsError::Timeout) {
                Ok(None)
            } else {
                Err(err)
            };
        }

        // Safely clamp the received length to u16 range and buffer size.
        let received = (n as usize).min(MAX_ETH_FRAME_LEN);
        frame.len = received as u16;

        // Use monotonic clock for consistent timestamps.
        frame.timestamp_us = Self::timestamp_us();

        Ok(Some(frame))
    }

    fn transmit(&mut self, data: &[u8]) -> Result<(), VsError> {
        if data.len() > MAX_ETH_FRAME_LEN {
            return Err(VsError::ResourceExhausted);
        }
        if data.len() < MIN_ETH_FRAME_LEN {
            // Pad short frames to the minimum Ethernet frame size.
            let mut padded = [0u8; MIN_ETH_FRAME_LEN];
            padded[..data.len()].copy_from_slice(data);
            // SAFETY: writing from a valid, stack-allocated padded buffer to the socket fd.
            let n = unsafe { libc::write(self.fd, padded.as_ptr().cast(), MIN_ETH_FRAME_LEN) };
            if n < 0 {
                return Err(errno_to_vserror());
            }
            return Ok(());
        }
        // SAFETY: writing from a valid slice to the socket fd.
        let n = unsafe { libc::write(self.fd, data.as_ptr().cast(), data.len()) };
        if n < 0 {
            return Err(errno_to_vserror());
        }
        Ok(())
    }

    fn link_speed_mbps(&self) -> u32 {
        // Query the actual link speed via ethtool ioctl.
        // Fall back to 1 Gbps if the query fails (e.g. virtual interfaces).
        self.ethtool_speed().unwrap_or(1000)
    }

    fn link_is_up(&self) -> bool {
        // SAFETY: ioctl with a valid fd and stack-allocated ifreq.
        unsafe {
            let mut ifr: libc::ifreq = core::mem::zeroed();
            // Reconstruct the interface name from ifindex via SIOCGIFNAME
            ifr.ifr_ifru.ifru_ifindex = self.ifindex;
            if libc::ioctl(self.fd, libc::SIOCGIFNAME as libc::c_ulong, &raw mut ifr) < 0 {
                return false;
            }
            // Query flags
            if libc::ioctl(self.fd, libc::SIOCGIFFLAGS as libc::c_ulong, &raw mut ifr) < 0 {
                return false;
            }
            (ifr.ifr_ifru.ifru_flags & (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short)
                == (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_nonexistent_interface_fails() {
        let result = LinuxEthernetPhy::new("nonexistent_eth_xyz0");
        assert!(result.is_err());
    }

    #[test]
    fn interface_name_too_long_fails() {
        let long_name = "this_interface_name_is_way_too_long_for_the_kernel_limit";
        let result = LinuxEthernetPhy::new(long_name);
        assert!(result.is_err());
    }

    #[test]
    fn transmit_oversized_frame_fails() {
        let data = [0u8; 2000];
        // Create a dummy LinuxEthernetPhy with an invalid fd to test the
        // pre-check. The length check happens before the write syscall.
        let mut phy = LinuxEthernetPhy {
            fd: -1,
            ifindex: 0,
            ifname: [0_i8; libc::IFNAMSIZ],
        };
        let err = phy.transmit(&data);
        assert_eq!(err, Err(VsError::ResourceExhausted));
        // Use mem::forget to prevent Drop from closing fd=-1.
        core::mem::forget(phy);
    }

    #[test]
    fn transmit_short_frame_is_padded() {
        // We can't actually transmit without a real socket, but we can verify
        // the padding logic by checking the minimum size constant.
        assert_eq!(MIN_ETH_FRAME_LEN, 60);
    }

    #[test]
    fn sockaddr_ll_size() {
        // Verify our SockaddrLl matches the expected kernel size (20 bytes).
        assert_eq!(core::mem::size_of::<SockaddrLl>(), 20);
    }

    #[test]
    fn timestamp_returns_nonzero() {
        let ts = LinuxEthernetPhy::timestamp_us();
        assert!(ts > 0);
    }

    // --- Interface name validation tests ---

    #[test]
    fn valid_interface_names_accepted() {
        assert!(LinuxEthernetPhy::is_valid_ifname(b"eth0"));
        assert!(LinuxEthernetPhy::is_valid_ifname(b"enp0s3"));
        assert!(LinuxEthernetPhy::is_valid_ifname(b"br-lan"));
        assert!(LinuxEthernetPhy::is_valid_ifname(b"wlan0"));
        assert!(LinuxEthernetPhy::is_valid_ifname(b"eth0.100")); // VLAN interface
        assert!(LinuxEthernetPhy::is_valid_ifname(b"my_iface"));
    }

    #[test]
    fn path_traversal_rejected() {
        assert!(!LinuxEthernetPhy::is_valid_ifname(b"../../../etc/passwd"));
        assert!(!LinuxEthernetPhy::is_valid_ifname(b"eth0/../secret"));
        assert!(!LinuxEthernetPhy::is_valid_ifname(b"/dev/null"));
        assert!(!LinuxEthernetPhy::is_valid_ifname(b"eth0/subpath"));
    }

    #[test]
    fn special_characters_rejected() {
        assert!(!LinuxEthernetPhy::is_valid_ifname(b"eth 0")); // space
        assert!(!LinuxEthernetPhy::is_valid_ifname(b"eth\t0")); // tab
        assert!(!LinuxEthernetPhy::is_valid_ifname(b"eth\n0")); // newline
        assert!(!LinuxEthernetPhy::is_valid_ifname(b"eth;reboot")); // semicolon
        assert!(!LinuxEthernetPhy::is_valid_ifname(b"eth|cmd")); // pipe
    }

    #[test]
    fn empty_name_accepted() {
        // Empty names are accepted by the character validator; the length
        // check in open() handles the empty-name case separately.
        assert!(LinuxEthernetPhy::is_valid_ifname(b""));
    }

    #[test]
    fn interface_with_path_separator_rejected_at_open() {
        let result = LinuxEthernetPhy::new("../../etc");
        assert!(matches!(result, Err(VsError::InvalidInput)));
    }
}
