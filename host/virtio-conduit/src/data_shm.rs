// SPDX-License-Identifier: Apache-2.0
//
// Conduit data-SHM creation helper.
//
// The libkrun VMM allocates the virtio SHM region but needs the
// backing POSIX named SHM to follow the conduit naming convention so
// the host-side Bifrost runtime can open it by name. This helper
// keeps that naming + shm_open / ftruncate dance in the crate that
// owns the conduit protocol, so libkrun only wires the resulting
// File into its guest-memory map.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::FromRawFd;

/// Create the per-process conduit data SHM (`/conduit-data-<pid>`) sized
/// to `size` bytes, or use `VIRTIO_CONDUIT_DATA_SHM_NAME` when a launcher
/// needs multiple processes to share one object. Returns the owning `File`
/// plus the published name so the caller can advertise it on the control SHM.
pub fn create_data_shm(size: usize) -> io::Result<(File, String)> {
    let name = std::env::var("VIRTIO_CONDUIT_DATA_SHM_NAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("/conduit-data-{}", std::process::id()));
    let open_existing = std::env::var_os("VIRTIO_CONDUIT_DATA_SHM_OPEN_EXISTING").is_some();
    let cname = CString::new(name.clone()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "conduit shm name contains NUL")
    })?;
    if !open_existing {
        unsafe {
            libc::shm_unlink(cname.as_ptr());
        }
    }
    let flags = if open_existing {
        libc::O_RDWR
    } else {
        libc::O_CREAT | libc::O_EXCL | libc::O_RDWR
    };
    let fd = unsafe { libc::shm_open(cname.as_ptr(), flags, 0o600) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    if !open_existing && unsafe { libc::ftruncate(fd, size as libc::off_t) } < 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
            libc::shm_unlink(cname.as_ptr());
        }
        return Err(err);
    }
    Ok((unsafe { File::from_raw_fd(fd) }, name))
}
