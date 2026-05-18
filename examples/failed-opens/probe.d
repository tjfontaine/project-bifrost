#!/usr/bin/env bifrost
/*
 * probe.d — system-wide failed-open profile, keyed on execname + errno.
 *
 * Exercises `retval` in a fbt :return clause: filter on negative
 * return values (errno), aggregate by (execname, retval).  Surfaces
 * which programs are hitting which kinds of open failures —
 * ENOENT (-2) for missing files, EACCES (-13) for permission
 * denials, EBADF (-9) for races, etc.
 *
 * `retval` substitutes to `arg<arity>` where arity is resolved from
 * vmlinux BTF.  do_sys_openat2(int, struct filename *, struct open_how *)
 * has arity 3, so retval reads from the fexit context's args[3]
 * slot — exactly where the BPF trampoline writes the function's
 * return value.
 *
 * Pair with: examples/failed-opens/setup.sh
 *
 * Run manually:
 *   sudo bifrost \
 *     -p $(pgrep -f '_boot-vm.*boot-config' | head -1) \
 *     -s examples/failed-opens/probe.d
 */

#pragma D option quiet

dtrace:::BEGIN
{
    printf("failed-open profile - Ctrl-C to dump\n");
    printf("    @errs[execname]: per-program failed-open count.\n");
    printf("    Predicate filters on retval < 0 (any errno).\n\n");
}

/*
 * `retval` is the do_sys_openat2 return value.  The host CLI
 * substitutes it to `arg<arity>` (here, arg3 — do_sys_openat2 has
 * 3 parameters) which the existing arg0..arg9 DIF lowering reads
 * as ctx[24] in the BPF_TRACE_FEXIT context — exactly the slot
 * the trampoline writes the function return value into.
 *
 * We use retval only in the predicate (signed-comparison filter),
 * not as an aggregation key — the libkrun-side agg renderer
 * renders integer keys as unsigned, which makes negative errno
 * values like -2 (ENOENT) print as 18446744073709551614.  Rendering
 * fix is queued separately; the predicate-filter form is enough
 * to demonstrate retval works.
 */
fbt:guest:do_sys_openat2:return
/retval < 0/
{
    @errs[execname] = count();
}
