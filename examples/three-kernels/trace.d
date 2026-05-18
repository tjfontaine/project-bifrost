/*
 * three-kernels — ONE D source, ONE shared clause, three kernels.
 *
 * macOS host + Linux smolvm + FreeBSD QEMU all attach the same
 * `profile:::tick-100ms` clause via the host's `route_clauses`
 * fan-out.  Each kernel takes a different attach path under the
 * hood — Linux via `perf_event_create_kernel_counter`,
 * FreeBSD via the kernel `profile` provider, macOS via a
 * child `dtrace(1)` — but the frontend has zero per-OS
 * branches.
 *
 * The shared `@triplet["all"] = count()` agg folds every kernel's
 * contribution into one cross-target row whose `contributors:`
 * map names all three target ids — the literal evidence the
 * cross-kernel demo checks for.
 */

#pragma D option quiet

profile:::tick-100ms
{
    trace(timestamp);
    @triplet["all"] = count();
}
