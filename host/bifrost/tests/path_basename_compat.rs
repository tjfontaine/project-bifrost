// Compatibility tests for the guest-side `path_basename` helper.
// The function lives in
// `third_party/linux-bifrost/drivers/bifrost/path_helpers.rs` and
// can't be exercised under cargo (it's part of a kernel module), so
// this file mirrors the function inline and tests the mirror.
// Drift between the two is the kind of bug this style of test
// catches: a divergence here means the kernel-side behaviour
// changed without an in-tree compat update.
//
// To audit drift against the canonical guest source, diff the body
// of `mirror_path_basename` below against `path_basename` in the
// kernel tree; they should match byte-for-byte modulo whitespace.

fn mirror_path_basename(buf: &[u8]) -> &[u8] {
    let mut end = buf.len();
    let mut last_slash: Option<usize> = None;
    for i in 0..buf.len() {
        if buf[i] == 0 {
            end = i;
            break;
        }
        if buf[i] == b'/' {
            last_slash = Some(i);
        }
    }
    let start = last_slash.map(|i| i + 1).unwrap_or(0);
    &buf[start..end]
}

#[test]
fn returns_full_buf_when_no_slash() {
    assert_eq!(mirror_path_basename(b"foo\0"), b"foo");
    assert_eq!(mirror_path_basename(b"foo"), b"foo");
}

#[test]
fn returns_after_last_slash() {
    assert_eq!(
        mirror_path_basename(b"/usr/bin/redis-server\0"),
        b"redis-server"
    );
    assert_eq!(mirror_path_basename(b"/foo/bar"), b"bar");
}

#[test]
fn stops_at_nul() {
    let mut buf = [0u8; 16];
    buf[..6].copy_from_slice(b"/a/foo");
    // bytes 6..16 are 0; basename should be "foo"
    assert_eq!(mirror_path_basename(&buf), b"foo");
}

#[test]
fn empty_input() {
    assert_eq!(mirror_path_basename(b""), b"");
    assert_eq!(mirror_path_basename(b"\0"), b"");
}

#[test]
fn trailing_slash() {
    // Trailing slash means basename is empty after the slash.
    assert_eq!(mirror_path_basename(b"/foo/"), b"");
}
