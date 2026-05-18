// Pre-flight: verify a `shm_open`-backed fd is a real
// kernel-object handle that survives the vhost-user fd-passing
// path. vhost-user sends region fds over a UNIX socket via
// `SCM_RIGHTS`; the recipient must be able to `mmap` what it
// received and see the same pages the sender wrote. If this
// breaks on macOS, the entire vhost-user transport migration is
// blocked and falls back to the two-adapter design.
//
// The test stays in-process: a `socketpair` connects two fds in
// the same task, one half sends the SHM fd via `sendmsg` +
// SCM_RIGHTS, the other receives it via `recvmsg`, dups the fd
// number to a fresh slot, mmaps it, and reads the sentinel the
// sender wrote through the *original* fd. Cross-fd, same-process
// is enough to prove the kernel object is shared — vhost-user's
// behavior across actual process boundaries is the same kernel
// path with a longer socket.

use std::ffi::CString;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;

fn shm_create(name: &str, size: usize) -> OwnedFd {
    let cname = CString::new(name).unwrap();
    unsafe { libc::shm_unlink(cname.as_ptr()) };
    let fd = unsafe {
        libc::shm_open(
            cname.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
            0o600,
        )
    };
    assert!(fd >= 0, "shm_open: {}", std::io::Error::last_os_error());
    let rc = unsafe { libc::ftruncate(fd, size as libc::off_t) };
    assert_eq!(rc, 0, "ftruncate: {}", std::io::Error::last_os_error());
    unsafe { libc::shm_unlink(cname.as_ptr()) };
    unsafe { OwnedFd::from_raw_fd(fd) }
}

fn mmap_rw(fd: RawFd, size: usize) -> *mut u8 {
    let p = unsafe {
        libc::mmap(
            ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    assert!(
        p != libc::MAP_FAILED,
        "mmap: {}",
        std::io::Error::last_os_error()
    );
    p.cast()
}

fn munmap(p: *mut u8, size: usize) {
    let rc = unsafe { libc::munmap(p.cast(), size) };
    assert_eq!(rc, 0);
}

// Send a single fd over a connected UNIX socket via SCM_RIGHTS.
// Sends one zero byte as the message payload because some BSD
// implementations reject zero-length cmsg packets.
fn send_fd(sock: RawFd, fd: RawFd) {
    let mut byte: u8 = 0;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut cmsg_buf = [0u8; unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) as usize }];
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_buf.len() as _;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        assert!(!cmsg.is_null());
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
        ptr::copy_nonoverlapping(&fd, libc::CMSG_DATA(cmsg).cast::<RawFd>(), 1);
    }

    let n = unsafe { libc::sendmsg(sock, &msg, 0) };
    assert_eq!(n, 1, "sendmsg: {}", std::io::Error::last_os_error());
}

fn recv_fd(sock: RawFd) -> OwnedFd {
    let mut byte: u8 = 0;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut cmsg_buf = [0u8; unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) as usize }];
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_buf.len() as _;

    let n = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    assert_eq!(n, 1, "recvmsg: {}", std::io::Error::last_os_error());

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        assert!(!cmsg.is_null(), "no cmsg received");
        assert_eq!((*cmsg).cmsg_level, libc::SOL_SOCKET);
        assert_eq!((*cmsg).cmsg_type, libc::SCM_RIGHTS);
        let mut fd: RawFd = -1;
        ptr::copy_nonoverlapping(libc::CMSG_DATA(cmsg).cast::<RawFd>(), &mut fd, 1);
        assert!(fd >= 0, "received bogus fd");
        OwnedFd::from_raw_fd(fd)
    }
}

#[test]
fn shm_open_fd_survives_scm_rights() {
    const SIZE: usize = 4096;
    let name = format!("/bifrost-shm-test-{}", std::process::id());

    // Sender side: create the SHM region, mmap it, and write a
    // sentinel through the original fd.
    let sender_fd = shm_create(&name, SIZE);
    let sender_p = mmap_rw(sender_fd.as_raw_fd(), SIZE);
    let sentinel: [u8; 8] = *b"BFR-PASS";
    unsafe {
        ptr::copy_nonoverlapping(sentinel.as_ptr(), sender_p, sentinel.len());
    }

    // Socketpair carries the fd via SCM_RIGHTS.
    let mut sv = [-1i32; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
    assert_eq!(rc, 0, "socketpair: {}", std::io::Error::last_os_error());
    let (tx, rx) = unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) };

    send_fd(tx.as_raw_fd(), sender_fd.as_raw_fd());
    let recv_fd_owned = recv_fd(rx.as_raw_fd());

    // The received fd is a distinct fd number pointing at the
    // same kernel object. Map it and read the sentinel back.
    assert_ne!(
        recv_fd_owned.as_raw_fd(),
        sender_fd.as_raw_fd(),
        "received fd should be a separate descriptor entry"
    );
    let recv_p = mmap_rw(recv_fd_owned.as_raw_fd(), SIZE);
    let mut readback = [0u8; 8];
    unsafe {
        ptr::copy_nonoverlapping(recv_p, readback.as_mut_ptr(), readback.len());
    }
    assert_eq!(
        readback, sentinel,
        "fd round-tripped via SCM_RIGHTS did not see sender's write"
    );

    // Reverse direction: write from the recipient and confirm the
    // sender sees it. This proves the mapping is truly shared, not
    // a copy-on-first-mmap snapshot.
    let echo: [u8; 8] = *b"ECHO-OK!";
    unsafe {
        ptr::copy_nonoverlapping(echo.as_ptr(), recv_p, echo.len());
        let mut buf = [0u8; 8];
        ptr::copy_nonoverlapping(sender_p, buf.as_mut_ptr(), buf.len());
        assert_eq!(buf, echo, "sender did not observe receiver's write");
    }

    munmap(sender_p, SIZE);
    munmap(recv_p, SIZE);
}
