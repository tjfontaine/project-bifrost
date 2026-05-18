#!/usr/bin/env bifrost
/*
 * redis-smoke-test probe.
 *
 * Trivial raw-tracepoint body against sched_switch, which fires while
 * the Redis guest is alive. This keeps the release smoke test
 * independent of the current smolvm host port-publishing backend.
 *
 * Run:
 *   sudo bifrost \
 *     -p $(pgrep -f '_boot-vm.*boot-config' | head -1) \
 *     -s examples/redis-smoke-test/probe.d
 */

#pragma D option quiet

tracepoint:guest:sched:sched_switch { x = 1; }
