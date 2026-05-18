/*
 * tracemem.d — tracemem primer.
 *
 * Demonstrates `tracemem(addr, len)` as a DTRACEACT_TRACEMEM
 * action: the bifrost host CLI emits a per-fire record carrying
 * `len` raw bytes from `addr` (treated as a kernel pointer),
 * and the renderer prints a libdtrace-style hex/ASCII dump.
 *
 * Run:
 *   sudo host/runtime/bifrost \
 *     -s examples/primers/tracemem.d \
 *     --emit-ebpf /tmp/tracemem.bfr7
 *
 * Each `do_sys_openat2` entry will dump 32 bytes from the kernel
 * pointer in `arg1` (the filename pointer).  Kernel pointers
 * that fault (e.g. `arg1 == NULL`) leave the buffer with zeros;
 * the record still emits.
 */

fbt:guest:do_sys_openat2:entry
{
    tracemem(arg1, 32);
}
