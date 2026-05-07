// SPDX-License-Identifier: Apache-2.0
//! `SocketCAN` implementation of the [`CanBus`] trait.
//!
//! Uses raw `libc` FFI to interact with the Linux `SocketCAN` subsystem.
//! Supports both classic CAN and CAN-FD frames with hardware-level
//! filtering and bus-off detection via netlink.

use vs_hal::{CanBus, CanError, CanErrorCounters, RawCanFrame};
use vs_types::VsError;

use crate::errno_to_vserror;

// ---------------------------------------------------------------------------
// Linux CAN kernel constants and structures
// ---------------------------------------------------------------------------

const PF_CAN: libc::c_int = 29;
const AF_CAN: libc::c_int = PF_CAN;
const CAN_RAW: libc::c_int = 1;
const SOL_CAN_RAW: libc::c_int = 101;
const CAN_RAW_FD_FRAMES: libc::c_int = 5;
const CAN_RAW_FILTER: libc::c_int = 1;
const SIOCGIFINDEX: libc::c_ulong = 0x8933;

/// CAN controller state values from `<linux/can/netlink.h>`.
const CAN_STATE_ERROR_ACTIVE: u32 = 0;
const _CAN_STATE_ERROR_WARNING: u32 = 1;
const _CAN_STATE_ERROR_PASSIVE: u32 = 2;
const CAN_STATE_BUS_OFF: u32 = 3;

/// Classic CAN frame (matches `struct can_frame` from `<linux/can.h>`).
#[repr(C)]
#[derive(Clone, Copy)]
struct KernelCanFrame {
    can_id: u32,
    can_dlc: u8,
    __pad: u8,
    __res0: u8,
    len8_dlc: u8,
    data: [u8; 8],
}

/// CAN-FD frame (matches `struct canfd_frame` from `<linux/can.h>`).
#[repr(C)]
#[derive(Clone, Copy)]
struct KernelCanFdFrame {
    can_id: u32,
    len: u8,
    flags: u8,
    __res0: u8,
    __res1: u8,
    data: [u8; 64],
}

/// Socket address for CAN (matches `struct sockaddr_can`).
#[repr(C)]
#[allow(clippy::struct_field_names)]
struct SockaddrCan {
    can_family: libc::sa_family_t,
    can_ifindex: libc::c_int,
    _padding: [u8; 8],
}

/// Kernel CAN filter (matches `struct can_filter` from `<linux/can.h>`).
#[repr(C)]
#[derive(Clone, Copy)]
struct KernelCanFilter {
    can_id: u32,
    can_mask: u32,
}

/// Mask bits in `can_id`.
const CAN_EFF_FLAG: u32 = 0x8000_0000;
#[cfg(test)]
const CAN_RTR_FLAG: u32 = 0x4000_0000;
const CAN_ERR_FLAG: u32 = 0x2000_0000;
const CAN_EFF_MASK: u32 = 0x1FFF_FFFF;
const CAN_SFF_MASK: u32 = 0x0000_07FF;
/// Inverted filter flag — filter matches when the frame does NOT match.
const _CAN_INV_FILTER: u32 = 0x2000_0000;

/// Maximum number of CAN filters per socket.
const MAX_CAN_FILTERS: usize = 64;

// ---------------------------------------------------------------------------
// CAN error frame decoding constants (from <linux/can/error.h>)
// ---------------------------------------------------------------------------

const CAN_ERR_BUSERROR: u32 = 0x0000_0200;
const CAN_ERR_BUSOFF: u32 = 0x0000_0040;
const CAN_ERR_CRTL: u32 = 0x0000_0004;
const CAN_ERR_ACK: u32 = 0x0000_0020;

/// Bit positions in `data[1]` for controller state.
const CAN_ERR_CRTL_RX_OVERFLOW: u8 = 0x01;
const CAN_ERR_CRTL_TX_OVERFLOW: u8 = 0x02;
const CAN_ERR_CRTL_RX_PASSIVE: u8 = 0x10;
const CAN_ERR_CRTL_TX_PASSIVE: u8 = 0x20;

/// Bit positions in `data[2]` for protocol error type.
const CAN_ERR_PROT_BIT: u8 = 0x01;
const CAN_ERR_PROT_FORM: u8 = 0x02;
const CAN_ERR_PROT_STUFF: u8 = 0x04;

// ---------------------------------------------------------------------------
// Public filter descriptor
// ---------------------------------------------------------------------------

/// A CAN acceptance filter.
///
/// Only frames matching `(received_id & mask) == (id & mask)` are delivered.
#[derive(Debug, Clone, Copy)]
pub struct CanFilter {
    /// CAN ID to match.
    pub id: u32,
    /// Mask applied to both frame ID and filter ID before comparison.
    pub mask: u32,
    /// Whether the filter uses extended (29-bit) IDs.
    pub is_extended: bool,
}

// ---------------------------------------------------------------------------
// LinuxCanBus
// ---------------------------------------------------------------------------

/// CAN bus implementation for Linux via `SocketCAN`.
///
/// # Example
///
/// ```no_run
/// use vs_hal_linux::LinuxCanBus;
/// use vs_hal::CanBus;
///
/// let mut can = LinuxCanBus::new("can0", 500_000).expect("open can0");
/// if let Ok(Some(frame)) = can.receive() {
///     println!("Received CAN frame: id={:#x}", frame.id);
/// }
/// ```
pub struct LinuxCanBus {
    fd: libc::c_int,
    bitrate: u32,
    fd_enabled: bool,
    /// Cached interface name for sysfs queries (null-terminated).
    ifname: [u8; libc::IFNAMSIZ],
    /// Last observed CAN error from an error frame.
    last_error: CanError,
    /// Cached error counters (updated on each error frame).
    error_counters: CanErrorCounters,
    /// Last successfully read monotonic timestamp (microseconds).
    last_timestamp_us: u64,
}

/// `LinuxCanBus` owns its file descriptor and is safe to move between threads,
/// but must not be shared without external synchronization.
///
/// SAFETY: The fd is used exclusively through `&mut self` methods (receive/transmit)
/// and the read-only queries (is_bus_off, etc.) access either atomic kernel state via
/// sysfs or immutable cached values. No concurrent access to the fd is possible through
/// the public API since all IO methods require `&mut self`.
unsafe impl Send for LinuxCanBus {}

impl LinuxCanBus {
    /// Open a `SocketCAN` interface by name (e.g. `"can0"`, `"vcan0"`).
    ///
    /// The socket is opened in non-blocking mode so that [`CanBus::receive`]
    /// returns `Ok(None)` when no frame is available.
    pub fn new(interface: &str, bitrate: u32) -> Result<Self, VsError> {
        Self::open(interface, bitrate, false)
    }

    /// Open a `SocketCAN` interface with CAN-FD support enabled.
    pub fn new_fd(interface: &str, bitrate: u32) -> Result<Self, VsError> {
        Self::open(interface, bitrate, true)
    }

    /// Install CAN acceptance filters on this socket.
    ///
    /// Only frames matching at least one filter will be delivered. Passing an
    /// empty slice removes all filters (receive-all). At most
    /// `MAX_CAN_FILTERS` (64) filters are accepted.
    pub fn set_filters(&mut self, filters: &[CanFilter]) -> Result<(), VsError> {
        if filters.len() > MAX_CAN_FILTERS {
            return Err(VsError::InvalidInput);
        }

        if filters.is_empty() {
            // Remove all filters → receive everything.
            // SAFETY: passing a null pointer with len 0 clears the filter list.
            let ret = unsafe {
                libc::setsockopt(self.fd, SOL_CAN_RAW, CAN_RAW_FILTER, core::ptr::null(), 0)
            };
            return if ret < 0 {
                Err(errno_to_vserror())
            } else {
                Ok(())
            };
        }

        let mut kfilters = [KernelCanFilter {
            can_id: 0,
            can_mask: 0,
        }; MAX_CAN_FILTERS];

        for (i, f) in filters.iter().enumerate() {
            let mut id = f.id;
            let mut mask = f.mask;
            if f.is_extended {
                id |= CAN_EFF_FLAG;
                mask |= CAN_EFF_FLAG;
            }
            kfilters[i] = KernelCanFilter {
                can_id: id,
                can_mask: mask,
            };
        }

        let optlen = (filters.len() * core::mem::size_of::<KernelCanFilter>()) as libc::socklen_t;

        // SAFETY: kfilters is valid stack memory, optlen is bounded.
        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                SOL_CAN_RAW,
                CAN_RAW_FILTER,
                kfilters.as_ptr().cast(),
                optlen,
            )
        };
        if ret < 0 {
            Err(errno_to_vserror())
        } else {
            Ok(())
        }
    }

    /// Validate that an interface name contains only safe characters.
    ///
    /// Rejects `/`, `.`, spaces, and other characters that could cause
    /// path traversal or injection in sysfs paths.
    fn is_valid_ifname(name: &[u8]) -> bool {
        for &b in name {
            if b == 0 {
                break;
            } // null terminator
            match b {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-' => {}
                _ => return false, // reject /, ., space, etc.
            }
        }
        true
    }

    fn open(interface: &str, bitrate: u32, enable_fd: bool) -> Result<Self, VsError> {
        if interface.len() >= libc::IFNAMSIZ {
            return Err(VsError::InvalidInput);
        }

        // Validate interface name contains only safe characters (prevent
        // path traversal in sysfs reads).
        if !Self::is_valid_ifname(interface.as_bytes()) {
            return Err(VsError::InvalidInput);
        }

        // Cache the interface name for sysfs queries.
        let mut ifname = [0u8; libc::IFNAMSIZ];
        for (i, &b) in interface.as_bytes().iter().enumerate() {
            ifname[i] = b;
        }

        // SAFETY: creating a raw CAN socket. All pointers are to valid
        // stack-allocated structures. We check return values for errors.
        unsafe {
            // 1. Create socket
            let fd = libc::socket(
                AF_CAN,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                CAN_RAW,
            );
            if fd < 0 {
                return Err(errno_to_vserror());
            }

            // 2. Resolve interface name to index via libc::ifreq
            let mut ifr: libc::ifreq = core::mem::zeroed();
            for (i, &b) in interface.as_bytes().iter().enumerate() {
                ifr.ifr_name[i] = libc::c_char::try_from(b).map_err(|_| VsError::InvalidInput)?;
            }
            if libc::ioctl(fd, SIOCGIFINDEX, &raw mut ifr) < 0 {
                libc::close(fd);
                return Err(errno_to_vserror());
            }

            // 3. Bind to the CAN interface
            let addr = SockaddrCan {
                can_family: AF_CAN as libc::sa_family_t,
                can_ifindex: ifr.ifr_ifru.ifru_ifindex,
                _padding: [0u8; 8],
            };
            let addr_ptr: *const SockaddrCan = &raw const addr;
            if libc::bind(
                fd,
                addr_ptr.cast::<libc::sockaddr>(),
                core::mem::size_of::<SockaddrCan>() as libc::socklen_t,
            ) < 0
            {
                libc::close(fd);
                return Err(errno_to_vserror());
            }

            // 4. Enable CAN-FD if requested
            if enable_fd {
                let enable: libc::c_int = 1;
                if libc::setsockopt(
                    fd,
                    SOL_CAN_RAW,
                    CAN_RAW_FD_FRAMES,
                    core::ptr::from_ref(&enable).cast(),
                    core::mem::size_of::<libc::c_int>() as libc::socklen_t,
                ) < 0
                {
                    libc::close(fd);
                    return Err(errno_to_vserror());
                }
            }

            // 5. Enable error frames so we can track bus-off / error-passive
            let err_mask: u32 = CAN_ERR_BUSOFF | CAN_ERR_CRTL | CAN_ERR_BUSERROR | CAN_ERR_ACK;
            // CAN_RAW_ERR_FILTER = 2
            const CAN_RAW_ERR_FILTER: libc::c_int = 2;
            if libc::setsockopt(
                fd,
                SOL_CAN_RAW,
                CAN_RAW_ERR_FILTER,
                core::ptr::from_ref(&err_mask).cast(),
                core::mem::size_of::<u32>() as libc::socklen_t,
            ) < 0
            {
                libc::close(fd);
                return Err(errno_to_vserror());
            }

            Ok(Self {
                fd,
                bitrate,
                fd_enabled: enable_fd,
                ifname,
                last_error: CanError::None,
                error_counters: CanErrorCounters {
                    tx_error_count: 0,
                    rx_error_count: 0,
                },
                last_timestamp_us: 0,
            })
        }
    }

    /// Read the Linux network interface operational state from sysfs.
    ///
    /// Reads `/sys/class/net/<iface>/operstate` which returns the standard
    /// Linux network `operstate` (e.g. "up", "down"), **not** the CAN
    /// controller state machine (error-active / error-passive / bus-off).
    /// We map "down" to `CAN_STATE_BUS_OFF` as a conservative heuristic
    /// since a down CAN interface typically indicates bus-off or
    /// administrative shutdown.
    fn read_can_state_sysfs(&self) -> Option<u32> {
        // Build path: /sys/class/net/<ifname>/operstate
        // Note: this is the Linux network operstate, not the CAN-specific
        // state machine.  A dedicated CAN state node is not universally
        // available across all kernel versions.
        let mut path = [0u8; 128];
        let prefix = b"/sys/class/net/";
        let suffix = b"/operstate";

        if prefix.len() + libc::IFNAMSIZ + suffix.len() >= path.len() {
            return None;
        }

        let mut pos = 0;
        for &b in prefix {
            path[pos] = b;
            pos += 1;
        }
        for &b in &self.ifname {
            if b == 0 {
                break;
            }
            path[pos] = b;
            pos += 1;
        }
        for &b in suffix {
            path[pos] = b;
            pos += 1;
        }
        // null-terminate
        path[pos] = 0;

        // SAFETY: path is a valid null-terminated C string on the stack.
        unsafe {
            let fd = libc::open(path.as_ptr().cast(), libc::O_RDONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return None;
            }
            let mut buf = [0u8; 32];
            let n = libc::read(fd, buf.as_mut_ptr().cast(), buf.len());
            // SAFETY: fd was just opened successfully above; closing exactly once.
            // Close error is intentionally ignored for this sysfs helper fd:
            // close() on a read-only sysfs fd cannot lose data, and there is no
            // meaningful recovery action in a no_std context.
            let sysfs_close_ret = libc::close(fd);
            debug_assert!(sysfs_close_ret == 0, "close() failed on sysfs operstate fd");

            if n <= 0 {
                return None;
            }

            // operstate returns "up\n", "down\n", etc.
            // "down" means the interface is down (could be bus-off).
            let content = &buf[..n as usize];
            if content.starts_with(b"down") {
                // Interface is down — may indicate bus-off
                Some(CAN_STATE_BUS_OFF)
            } else if content.starts_with(b"up") {
                Some(CAN_STATE_ERROR_ACTIVE)
            } else {
                None
            }
        }
    }

    /// Read CAN error counters from sysfs.
    ///
    /// Reads `/sys/class/net/<iface>/statistics/tx_errors` and `rx_errors`.
    fn read_error_counters_sysfs(&self) -> (u16, u16) {
        let tx = self.read_sysfs_u64(b"/statistics/tx_errors");
        let rx = self.read_sysfs_u64(b"/statistics/rx_errors");
        (
            tx.unwrap_or(0).min(u16::MAX as u64) as u16,
            rx.unwrap_or(0).min(u16::MAX as u64) as u16,
        )
    }

    /// Read a single u64 value from a sysfs file under the interface directory.
    fn read_sysfs_u64(&self, suffix: &[u8]) -> Option<u64> {
        let mut path = [0u8; 128];
        let prefix = b"/sys/class/net/";

        let mut pos = 0;
        for &b in prefix {
            if pos >= path.len() - 1 {
                return None;
            }
            path[pos] = b;
            pos += 1;
        }
        for &b in &self.ifname {
            if b == 0 {
                break;
            }
            if pos >= path.len() - 1 {
                return None;
            }
            path[pos] = b;
            pos += 1;
        }
        for &b in suffix {
            if pos >= path.len() - 1 {
                return None;
            }
            path[pos] = b;
            pos += 1;
        }
        path[pos] = 0;

        // SAFETY: path is a valid null-terminated C string on the stack.
        // All pointers point to valid stack-allocated buffers.
        unsafe {
            let fd = libc::open(path.as_ptr().cast(), libc::O_RDONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return None;
            }
            let mut buf = [0u8; 32];
            let n = libc::read(fd, buf.as_mut_ptr().cast(), buf.len());
            // SAFETY: fd was just opened successfully above; closing exactly once.
            // Close error is intentionally ignored for this sysfs helper fd:
            // close() on a read-only sysfs fd cannot lose data, and there is no
            // meaningful recovery action in a no_std context.
            let sysfs_close_ret = libc::close(fd);
            debug_assert!(
                sysfs_close_ret == 0,
                "close() failed on sysfs statistics fd"
            );
            if n <= 0 {
                return None;
            }

            // Parse ASCII decimal, stripping trailing newline.
            let mut val: u64 = 0;
            for &ch in &buf[..n as usize] {
                if ch >= b'0' && ch <= b'9' {
                    val = val.saturating_mul(10).saturating_add((ch - b'0') as u64);
                } else {
                    break;
                }
            }
            Some(val)
        }
    }

    /// Get the current monotonic timestamp in microseconds.
    ///
    /// On failure, returns the last successfully read timestamp so that
    /// downstream consumers never see a spurious zero (consistent with the
    /// Ethernet and Timer HAL implementations).
    fn timestamp_us(&mut self) -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: ts is a valid stack-allocated timespec.
        let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &raw mut ts) };
        if ret != 0 {
            return self.last_timestamp_us;
        }
        let now = (ts.tv_sec as u64) * 1_000_000 + (ts.tv_nsec as u64) / 1_000;
        self.last_timestamp_us = now;
        now
    }

    /// Process a received error frame and update internal state.
    fn process_error_frame(&mut self, can_id: u32, data: &[u8]) {
        if can_id & CAN_ERR_BUSOFF != 0 {
            self.last_error = CanError::BusOff;
        } else if can_id & CAN_ERR_ACK != 0 {
            self.last_error = CanError::AckError;
        } else if can_id & CAN_ERR_BUSERROR != 0 && data.len() >= 3 {
            // Decode protocol error type from data[2].
            if data[2] & CAN_ERR_PROT_STUFF != 0 {
                self.last_error = CanError::BitStuffing;
            } else if data[2] & CAN_ERR_PROT_FORM != 0 {
                self.last_error = CanError::FormError;
            } else if data[2] & CAN_ERR_PROT_BIT != 0 {
                self.last_error = CanError::BitError;
            } else {
                self.last_error = CanError::CrcError;
            }
        } else if can_id & CAN_ERR_CRTL != 0 && data.len() >= 2 {
            if data[1] & (CAN_ERR_CRTL_RX_OVERFLOW | CAN_ERR_CRTL_TX_OVERFLOW) != 0 {
                self.last_error = CanError::Overrun;
            } else if data[1] & (CAN_ERR_CRTL_RX_PASSIVE | CAN_ERR_CRTL_TX_PASSIVE) != 0 {
                self.last_error = CanError::ErrorPassive;
            }
        }

        // Update error counters from sysfs (error frames don't carry TEC/REC
        // directly in all kernel versions).
        let (tx, rx) = self.read_error_counters_sysfs();
        self.error_counters.tx_error_count = tx;
        self.error_counters.rx_error_count = rx;
    }
}

impl Drop for LinuxCanBus {
    fn drop(&mut self) {
        if self.fd < 0 {
            return;
        }
        // SAFETY: closing a valid file descriptor exactly once.
        // The fd was obtained from socket() in new() and is owned exclusively
        // by this struct. No other code closes this fd.
        unsafe {
            let ret = libc::close(self.fd);
            debug_assert!(ret == 0, "close() failed on CAN socket fd");
        }
    }
}

impl CanBus for LinuxCanBus {
    fn receive(&mut self) -> Result<Option<RawCanFrame>, VsError> {
        if self.fd_enabled {
            self.receive_fd()
        } else {
            self.receive_classic()
        }
    }

    fn transmit(&mut self, frame: &RawCanFrame) -> Result<(), VsError> {
        if frame.is_fd || frame.dlc > 8 {
            self.transmit_fd(frame)
        } else {
            self.transmit_classic(frame)
        }
    }

    fn bitrate(&self) -> u32 {
        self.bitrate
    }

    fn is_bus_off(&self) -> bool {
        // Check cached error state first (updated via error frames).
        if matches!(self.last_error, CanError::BusOff) {
            return true;
        }
        // Fall back to sysfs for authoritative state.
        matches!(self.read_can_state_sysfs(), Some(CAN_STATE_BUS_OFF))
    }

    fn last_error(&self) -> CanError {
        self.last_error
    }

    fn error_counters(&self) -> CanErrorCounters {
        // Return fresh counters from sysfs rather than possibly stale cache.
        let (tx, rx) = self.read_error_counters_sysfs();
        CanErrorCounters {
            tx_error_count: tx,
            rx_error_count: rx,
        }
    }

    fn recover_bus_off(&mut self) -> Result<(), VsError> {
        // On Linux SocketCAN, bus-off recovery is triggered by bringing the
        // interface down and back up:
        //   ip link set canX down && ip link set canX up
        //
        // From userspace we can also write to the restart sysfs node:
        //   /sys/class/net/<iface>/device/restart
        // However that requires root. The standard approach is to set
        // CAN_CTRLMODE_BERR_REPORTING and let the driver auto-recover after
        // 128 * 11 recessive bits (per CAN spec).
        //
        // Here we attempt the sysfs restart, falling back to a no-op if it
        // fails (automatic recovery is the default for most drivers).
        let mut path = [0u8; 128];
        let prefix = b"/sys/class/net/";
        let suffix = b"/device/restart";

        let mut pos = 0;
        for &b in prefix {
            if pos >= path.len() - 1 {
                break;
            }
            path[pos] = b;
            pos += 1;
        }
        for &b in &self.ifname {
            if b == 0 {
                break;
            }
            if pos >= path.len() - 1 {
                break;
            }
            path[pos] = b;
            pos += 1;
        }
        for &b in suffix {
            if pos >= path.len() - 1 {
                break;
            }
            path[pos] = b;
            pos += 1;
        }
        path[pos] = 0;

        // SAFETY: path is a valid null-terminated string on the stack.
        // All pointers point to valid stack-allocated buffers.
        unsafe {
            let fd = libc::open(path.as_ptr().cast(), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd >= 0 {
                let val = b"1";
                libc::write(fd, val.as_ptr().cast(), 1);
                // SAFETY: fd was just opened successfully above; closing exactly once.
                // Close error is intentionally ignored for this sysfs helper fd:
                // this is a best-effort bus-off recovery write, and close() failure
                // on a sysfs node does not affect the main CAN socket.
                let sysfs_close_ret = libc::close(fd);
                debug_assert!(sysfs_close_ret == 0, "close() failed on sysfs restart fd");
            }
        }

        // Clear cached error state.
        self.last_error = CanError::None;
        Ok(())
    }
}

impl LinuxCanBus {
    fn receive_classic(&mut self) -> Result<Option<RawCanFrame>, VsError> {
        let mut kf = KernelCanFrame {
            can_id: 0,
            can_dlc: 0,
            __pad: 0,
            __res0: 0,
            len8_dlc: 0,
            data: [0u8; 8],
        };
        // SAFETY: reading into a valid, stack-allocated kernel CAN frame.
        let n = unsafe {
            libc::read(
                self.fd,
                core::ptr::from_mut(&mut kf).cast(),
                core::mem::size_of::<KernelCanFrame>(),
            )
        };
        if n < 0 {
            let err = errno_to_vserror();
            return if matches!(err, VsError::Timeout) {
                Ok(None) // EAGAIN — no frame available
            } else {
                Err(err)
            };
        }
        if (n as usize) < core::mem::size_of::<KernelCanFrame>() {
            return Err(VsError::BusError);
        }

        // Check for error frames and process them internally.
        if kf.can_id & CAN_ERR_FLAG != 0 {
            self.process_error_frame(kf.can_id, &kf.data);
            // Error frames are not returned to the caller — try to receive
            // the next data frame instead.
            return Ok(None);
        }

        let mut frame = kernel_to_raw_can(&kf);
        frame.timestamp_us = self.timestamp_us();
        Ok(Some(frame))
    }

    fn receive_fd(&mut self) -> Result<Option<RawCanFrame>, VsError> {
        let mut kf = KernelCanFdFrame {
            can_id: 0,
            len: 0,
            flags: 0,
            __res0: 0,
            __res1: 0,
            data: [0u8; 64],
        };
        // SAFETY: reading into a valid, stack-allocated kernel CAN-FD frame.
        let n = unsafe {
            libc::read(
                self.fd,
                core::ptr::from_mut(&mut kf).cast(),
                core::mem::size_of::<KernelCanFdFrame>(),
            )
        };
        if n < 0 {
            let err = errno_to_vserror();
            return if matches!(err, VsError::Timeout) {
                Ok(None)
            } else {
                Err(err)
            };
        }

        let received = n as usize;

        // Static assertion: KernelCanFdFrame must be at least as large as
        // KernelCanFrame so that a classic-sized read into an FD buffer is
        // guaranteed to have populated all the fields we copy below.
        const _: () = assert!(
            core::mem::size_of::<KernelCanFdFrame>() >= core::mem::size_of::<KernelCanFrame>(),
            "KernelCanFdFrame must be at least as large as KernelCanFrame"
        );

        // Check for error frames — they arrive as classic-sized frames.
        if received == core::mem::size_of::<KernelCanFrame>() {
            // SAFETY: The kernel wrote exactly sizeof(KernelCanFrame) bytes
            // into the `kf` buffer. KernelCanFdFrame and KernelCanFrame are
            // both #[repr(C)] with identical leading layout: can_id (u32)
            // followed by a length byte and padding bytes, then data. We
            // manually copy the relevant fields rather than casting between
            // struct types to avoid type-punning undefined behavior.
            let classic = KernelCanFrame {
                can_id: kf.can_id,
                can_dlc: kf.len,
                __pad: kf.flags,
                __res0: kf.__res0,
                len8_dlc: kf.__res1,
                data: {
                    let mut d = [0u8; 8];
                    d.copy_from_slice(&kf.data[..8]);
                    d
                },
            };
            if classic.can_id & CAN_ERR_FLAG != 0 {
                self.process_error_frame(classic.can_id, &classic.data);
                return Ok(None);
            }
            let mut frame = kernel_to_raw_can(&classic);
            frame.timestamp_us = self.timestamp_us();
            Ok(Some(frame))
        } else if received == core::mem::size_of::<KernelCanFdFrame>() {
            if kf.can_id & CAN_ERR_FLAG != 0 {
                self.process_error_frame(kf.can_id, &kf.data[..8]);
                return Ok(None);
            }
            let mut frame = kernel_fd_to_raw_can(&kf);
            frame.timestamp_us = self.timestamp_us();
            Ok(Some(frame))
        } else {
            Err(VsError::BusError)
        }
    }

    fn transmit_classic(&mut self, frame: &RawCanFrame) -> Result<(), VsError> {
        let kf = raw_can_to_kernel(frame);
        // SAFETY: writing a valid, stack-allocated kernel CAN frame.
        let n = unsafe {
            libc::write(
                self.fd,
                core::ptr::from_ref(&kf).cast(),
                core::mem::size_of::<KernelCanFrame>(),
            )
        };
        if n < 0 {
            return Err(errno_to_vserror());
        }
        Ok(())
    }

    fn transmit_fd(&mut self, frame: &RawCanFrame) -> Result<(), VsError> {
        let kf = raw_can_to_kernel_fd(frame);
        // SAFETY: writing a valid, stack-allocated kernel CAN-FD frame.
        let n = unsafe {
            libc::write(
                self.fd,
                core::ptr::from_ref(&kf).cast(),
                core::mem::size_of::<KernelCanFdFrame>(),
            )
        };
        if n < 0 {
            return Err(errno_to_vserror());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

fn kernel_to_raw_can(kf: &KernelCanFrame) -> RawCanFrame {
    let is_extended = kf.can_id & CAN_EFF_FLAG != 0;
    let id = if is_extended {
        kf.can_id & CAN_EFF_MASK
    } else {
        kf.can_id & CAN_SFF_MASK
    };

    let mut frame = RawCanFrame::zeroed();
    frame.id = id;
    frame.dlc = kf.can_dlc;
    frame.is_extended = is_extended;
    frame.is_fd = false;
    // Clamp copy length to the classic CAN maximum of 8 bytes.
    let copy_len = (kf.can_dlc as usize).min(8);
    frame.data[..copy_len].copy_from_slice(&kf.data[..copy_len]);
    frame
}

fn kernel_fd_to_raw_can(kf: &KernelCanFdFrame) -> RawCanFrame {
    let is_extended = kf.can_id & CAN_EFF_FLAG != 0;
    let id = if is_extended {
        kf.can_id & CAN_EFF_MASK
    } else {
        kf.can_id & CAN_SFF_MASK
    };

    let mut frame = RawCanFrame::zeroed();
    frame.id = id;
    frame.dlc = kf.len;
    frame.is_extended = is_extended;
    frame.is_fd = true;
    let copy_len = (kf.len as usize).min(64);
    frame.data[..copy_len].copy_from_slice(&kf.data[..copy_len]);
    frame
}

fn raw_can_to_kernel(frame: &RawCanFrame) -> KernelCanFrame {
    let mut can_id = frame.id;
    if frame.is_extended {
        can_id |= CAN_EFF_FLAG;
    }
    // Clamp DLC to 8 for classic CAN.
    let dlc = frame.dlc.min(8);
    let mut kf = KernelCanFrame {
        can_id,
        can_dlc: dlc,
        __pad: 0,
        __res0: 0,
        len8_dlc: 0,
        data: [0u8; 8],
    };
    kf.data[..dlc as usize].copy_from_slice(&frame.data[..dlc as usize]);
    kf
}

fn raw_can_to_kernel_fd(frame: &RawCanFrame) -> KernelCanFdFrame {
    let mut can_id = frame.id;
    if frame.is_extended {
        can_id |= CAN_EFF_FLAG;
    }
    // Clamp length to 64 for CAN-FD.
    let len = frame.dlc.min(64);
    let mut kf = KernelCanFdFrame {
        can_id,
        len,
        flags: 0,
        __res0: 0,
        __res1: 0,
        data: [0u8; 64],
    };
    kf.data[..len as usize].copy_from_slice(&frame.data[..len as usize]);
    kf
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_can_frame_size_is_16_bytes() {
        assert_eq!(core::mem::size_of::<KernelCanFrame>(), 16);
    }

    #[test]
    fn kernel_canfd_frame_size_is_72_bytes() {
        assert_eq!(core::mem::size_of::<KernelCanFdFrame>(), 72);
    }

    #[test]
    fn kernel_can_filter_size_is_8_bytes() {
        assert_eq!(core::mem::size_of::<KernelCanFilter>(), 8);
    }

    #[test]
    fn roundtrip_standard_id() {
        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x123;
        frame.dlc = 4;
        frame.data[0] = 0xDE;
        frame.data[1] = 0xAD;
        frame.data[2] = 0xBE;
        frame.data[3] = 0xEF;

        let kf = raw_can_to_kernel(&frame);
        let back = kernel_to_raw_can(&kf);
        assert_eq!(back.id, 0x123);
        assert_eq!(back.dlc, 4);
        assert_eq!(back.data[0], 0xDE);
        assert_eq!(back.data[3], 0xEF);
        assert!(!back.is_extended);
        assert!(!back.is_fd);
    }

    #[test]
    fn roundtrip_extended_id() {
        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x1234_5678;
        frame.dlc = 8;
        frame.is_extended = true;
        frame.data = [
            1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];

        let kf = raw_can_to_kernel(&frame);
        assert!(kf.can_id & CAN_EFF_FLAG != 0);

        let back = kernel_to_raw_can(&kf);
        assert_eq!(back.id, 0x1234_5678);
        assert!(back.is_extended);
        assert_eq!(back.data[0], 1);
        assert_eq!(back.data[7], 8);
    }

    #[test]
    fn roundtrip_fd_frame() {
        let mut frame = RawCanFrame::zeroed();
        frame.id = 0x7FF;
        frame.dlc = 64;
        frame.is_fd = true;
        for i in 0..64 {
            frame.data[i] = i as u8;
        }

        let kf = raw_can_to_kernel_fd(&frame);
        let back = kernel_fd_to_raw_can(&kf);
        assert_eq!(back.id, 0x7FF);
        assert_eq!(back.dlc, 64);
        assert!(back.is_fd);
        for i in 0..64 {
            assert_eq!(back.data[i], i as u8);
        }
    }

    #[test]
    fn dlc_clamped_to_8_for_classic() {
        let mut frame = RawCanFrame::zeroed();
        frame.dlc = 64; // would be invalid for classic CAN
        let kf = raw_can_to_kernel(&frame);
        assert_eq!(kf.can_dlc, 8);
    }

    #[test]
    fn dlc_clamped_to_64_for_fd() {
        let mut frame = RawCanFrame::zeroed();
        frame.dlc = 255;
        let kf = raw_can_to_kernel_fd(&frame);
        assert_eq!(kf.len, 64);
    }

    #[test]
    fn rtr_and_err_flags_stripped_from_id() {
        let kf = KernelCanFrame {
            can_id: 0x123 | CAN_RTR_FLAG | CAN_ERR_FLAG,
            can_dlc: 0,
            __pad: 0,
            __res0: 0,
            len8_dlc: 0,
            data: [0; 8],
        };
        let frame = kernel_to_raw_can(&kf);
        assert_eq!(frame.id, 0x123);
        assert!(!frame.is_extended);
    }

    #[test]
    fn open_nonexistent_interface_fails() {
        let result = LinuxCanBus::new("nonexistent_iface_xyz0", 500_000);
        assert!(result.is_err());
    }

    #[test]
    fn interface_name_too_long_fails() {
        let long_name = "a]repeating_interface_name_that_is_way_too_long_for_ifnamsiz";
        let result = LinuxCanBus::new(long_name, 500_000);
        assert!(result.is_err());
    }

    #[test]
    fn error_frame_decoded_as_bus_off() {
        let mut bus = LinuxCanBus {
            fd: -1,
            bitrate: 500_000,
            fd_enabled: false,
            ifname: [0u8; libc::IFNAMSIZ],
            last_error: CanError::None,
            error_counters: CanErrorCounters {
                tx_error_count: 0,
                rx_error_count: 0,
            },
            last_timestamp_us: 0,
        };
        bus.process_error_frame(CAN_ERR_FLAG | CAN_ERR_BUSOFF, &[0u8; 8]);
        assert_eq!(bus.last_error, CanError::BusOff);
        drop(bus);
    }

    #[test]
    fn error_frame_decoded_as_ack_error() {
        let mut bus = LinuxCanBus {
            fd: -1,
            bitrate: 500_000,
            fd_enabled: false,
            ifname: [0u8; libc::IFNAMSIZ],
            last_error: CanError::None,
            error_counters: CanErrorCounters {
                tx_error_count: 0,
                rx_error_count: 0,
            },
            last_timestamp_us: 0,
        };
        bus.process_error_frame(CAN_ERR_FLAG | CAN_ERR_ACK, &[0u8; 8]);
        assert_eq!(bus.last_error, CanError::AckError);
        drop(bus);
    }

    #[test]
    fn error_frame_decoded_as_stuff_error() {
        let mut bus = LinuxCanBus {
            fd: -1,
            bitrate: 500_000,
            fd_enabled: false,
            ifname: [0u8; libc::IFNAMSIZ],
            last_error: CanError::None,
            error_counters: CanErrorCounters {
                tx_error_count: 0,
                rx_error_count: 0,
            },
            last_timestamp_us: 0,
        };
        let mut data = [0u8; 8];
        data[2] = CAN_ERR_PROT_STUFF;
        bus.process_error_frame(CAN_ERR_FLAG | CAN_ERR_BUSERROR, &data);
        assert_eq!(bus.last_error, CanError::BitStuffing);
        drop(bus);
    }

    #[test]
    fn error_frame_decoded_as_overrun() {
        let mut bus = LinuxCanBus {
            fd: -1,
            bitrate: 500_000,
            fd_enabled: false,
            ifname: [0u8; libc::IFNAMSIZ],
            last_error: CanError::None,
            error_counters: CanErrorCounters {
                tx_error_count: 0,
                rx_error_count: 0,
            },
            last_timestamp_us: 0,
        };
        let mut data = [0u8; 8];
        data[1] = CAN_ERR_CRTL_RX_OVERFLOW;
        bus.process_error_frame(CAN_ERR_FLAG | CAN_ERR_CRTL, &data);
        assert_eq!(bus.last_error, CanError::Overrun);
        drop(bus);
    }
}
