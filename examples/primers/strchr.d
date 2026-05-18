#!/usr/bin/env bifrost
/*
 * strchr.d — first/last byte search in a user-string.
 *
 * `strchr(s, c)` returns a pointer to the first byte equal to
 * `c` in `s`, NULL if not found. `strrchr` is the same but
 * returns the last occurrence (search from end). Both use the
 * per-CPU 256-byte scratch buffer `copyinstr` writes into, so
 * the returned pointer is valid until the next copyinstr /
 * strchr / strrchr call in the same probe.
 *
 *   sudo bifrost -p $PID -s examples/primers/strchr.d
 *
 * Prints the basename of every opened path by chopping at the
 * last '/'. If `strrchr` returns NULL (path has no slash), the
 * predicate skips the fire.
 */

#pragma D option quiet

syscall::openat:entry
/strrchr(copyinstr(arg1), '/') != NULL/
{
    printf("basename=%s\n", strrchr(copyinstr(arg1), '/') + 1);
}
