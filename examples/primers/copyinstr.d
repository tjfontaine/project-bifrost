#!/usr/bin/env bifrost
/*
 * copyinstr.d — bounded user-string copy.
 *
 * `copyinstr(uaddr)` copies up to 256 bytes of NUL-terminated
 * user-space memory into a per-CPU scratch buffer and returns a
 * pointer BPF treats as a `string`. The scratch is reused across
 * calls in the same probe — callers must consume the result
 * before issuing a second copyinstr.
 *
 * Unlike DTrace's classic copyinstr, the bound is fixed at 256
 * bytes; longer paths are silently truncated. This matches the
 * BPF verifier's "bounded string-size" requirement.
 *
 *   sudo bifrost -p $PID -s examples/primers/copyinstr.d
 *
 * Should print the path arg of every openat(2) on the guest.
 */

#pragma D option quiet

syscall::openat:entry
{
    printf("open path=%s\n", copyinstr(arg1));
}
