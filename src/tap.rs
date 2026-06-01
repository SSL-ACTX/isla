// src/tap.rs
use nix::libc;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;

#[derive(Debug)]
pub enum TapError {
    Io(std::io::Error),
}

pub struct TapDevice {
    file: File,
    pub name: String,
}

impl TapDevice {
    /// Creates a new TAP device.
    /// This requires the binary to have CAP_NET_ADMIN privileges.
    pub fn new(name: &str) -> Result<Self, TapError> {
        // Open the character device for cloning network interfaces
        let file = File::options()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(TapError::Io)?;

        let fd = file.as_raw_fd();

        // Create an ifreq structure for the ioctl call
        // We use IFF_TAP (Layer 2) and IFF_NO_PI (No extra packet information)
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let ifr_name = name.as_bytes();
        let len = std::cmp::min(ifr_name.len(), libc::IFNAMSIZ - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(
                ifr_name.as_ptr(),
                ifr.ifr_name.as_mut_ptr() as *mut u8,
                len,
            );
            ifr.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as i16;
        }

        // TUNSETIFF ioctl registers the interface with the kernel
        unsafe {
            if libc::ioctl(fd, libc::TUNSETIFF as _, &ifr) < 0 {
                return Err(TapError::Io(std::io::Error::last_os_error()));
            }
        }

        let actual_name = unsafe {
            std::ffi::CStr::from_ptr(ifr.ifr_name.as_ptr())
                .to_string_lossy()
                .into_owned()
        };

        Ok(TapDevice {
            file,
            name: actual_name,
        })
    }

    /// Sets the file descriptor to non-blocking mode.
    /// Critical for batch processing loops.
    pub fn set_non_blocking(&mut self, non_blocking: bool) -> std::io::Result<()> {
        let fd = self.file.as_raw_fd();
        unsafe {
            let mut flags = libc::fcntl(fd, libc::F_GETFL);
            if flags < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if non_blocking {
                flags |= libc::O_NONBLOCK;
            } else {
                flags &= !libc::O_NONBLOCK;
            }
            if libc::fcntl(fd, libc::F_SETFL, flags) < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Reads a raw frame from the TAP interface
    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }

    /// Writes a raw frame to the TAP interface
    pub fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }
}
