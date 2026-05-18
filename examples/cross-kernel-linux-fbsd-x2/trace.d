/*
 * cross-kernel-linux-fbsd-x2 — one D source, two kernels.
 *
 * The north-star demo: one `bifrost orchestrate` invocation drives a
 * Linux smolvm and a FreeBSD QEMU guest in parallel, with a single
 * SHARED clause whose `@latency` aggregation folds across both
 * kernels via the host's cross-target reducer.
 *
 * Routing (host/bifrost/src/plan.rs `route_clauses` +
 * backend::TraceTarget::route_probe):
 *
 *   - `profile:::tick-100ms` is an `Either`-shaped probe.  It fans
 *     out to every plan target that can attach it.  The Linux
 *     backend lowers it to a
 *     BPF_PROG_TYPE_PERF_EVENT program attached via
 *     `perf_event_create_kernel_counter` (period_ns = 100,000,000);
 *     the FreeBSD path lowers it through libdtrace and attaches via
 *     the kernel-side `profile` provider.
 *
 *   - `trace(timestamp)` lands as per-fire records in the
 *     orchestrator's merged stream under each target's id.  `linux-a`
 *     and `fbsd-b` both surface their fires in host-wall-clock order.
 *
 *   - `@latency = quantize(timestamp & 0xff)` folds across both
 *     kernels via `merge::CrossTargetAggReducer` — the row's
 *     contributors map names BOTH `linux-a` and `fbsd-b`.
 */

#pragma D option quiet

profile:::tick-100ms
{
    trace(timestamp);
    @latency = quantize(timestamp & 0xff);
}
