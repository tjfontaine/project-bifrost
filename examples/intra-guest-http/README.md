# intra-guest-http

The "real samples" companion to [cross-domain-http](../cross-domain-http/README.md).

cross-domain-http drives `ab` from macOS through libkrun's TSI
port-forward, which intercepts at the userspace boundary and
translates host TCP → vsock → in-guest unix socket. The guest
kernel's TCP stack never sees the segments, so the
`bifrost::tcp_v4_do_rcv` clauses load and JIT cleanly but never
fire — the host-side `syscall::connect` clause is the only thing
populating `@reqs`, and `@rcv_lat` stays empty.

This demo runs the load generator **inside the guest** (`ab`
hitting `127.0.0.1:80` via the loopback interface), so traffic
loops back through the guest TCP stack. `tcp_v4_do_rcv` fires for
every inbound segment, `@rcv_lat` populates with thousands of
real samples, and `@reqs[pid]` shows both nginx workers and the
in-guest ab client threads side by side.

The demo splits into two halves:

- [`setup.sh`](setup.sh) boots `ubuntu:24.04` in smolvm,
  apt-installs nginx + apache2-utils, starts nginx as the
  entrypoint, and drives a continuous `ab` loop **inside the
  guest** via `smolvm machine exec`. No host port-forward needed
  (no host-side load generator).
- You run bifrost yourself in another shell, dtrace-style.

## What it shows

Three guest-side aggregations, all dumped together when you ^C
the bifrost trace:

1. **`@reqs[pid]` per-task segment count.** nginx forks one
   worker per CPU; the in-guest ab spawns one client thread per
   concurrency level. Both ends of the loopback show up here —
   the guest kernel sees segments arriving at both the listener
   socket (nginx workers) and the connect-side return path (ab
   threads).

2. **`@rcv_lat` quantize.** Power-of-two histogram of guest-side
   per-segment processing time. Real benchmark load fills
   thousands of samples and surfaces the bimodal shape: tight
   fast-path peak around 1-4 µs (TCP header parse + queue) plus
   a long tail under contention (socket lookup miss, congestion-
   control update, sk_data_ready wakeup).

3. **`gustack()` at each fire.** Frame-pointer build of nginx in
   Ubuntu 24.04+ walks cleanly into nginx worker frames; the ab
   side bottoms out in libc.

## Run

Two shells.

```sh
# shell 1 — keeps smolvm + in-guest ab loop running until ^C
examples/intra-guest-http/setup.sh
```

`setup.sh` prints the smolvm pid and the bifrost command to use.

```sh
# shell 2 — the trace itself.
# (assumes host/runtime/ is on PATH; see top-level README)
sudo bifrost -p $PID -s examples/intra-guest-http/probe.d
```

Three equivalent forms — pick whichever you prefer:

```sh
# 1. -s flag, like dtrace
sudo bifrost -p $PID -s examples/intra-guest-http/probe.d

# 2. inline D expression with -n, like `dtrace -n`
sudo bifrost -p $PID \
    -n 'bifrost::tcp_v4_do_rcv:entry { @[pid] = count(); }'

# 3. self-executing script (probe.d has #!/usr/bin/env bifrost)
sudo examples/intra-guest-http/probe.d -p $PID
```

When you have enough samples, ^C the bifrost CLI to dump
aggregations, then ^C `setup.sh` to tear down.

Override knobs on `setup.sh`:

```sh
AB_REQS=20000 AB_CONC=64 examples/intra-guest-http/setup.sh
```

## Files

- [`setup.sh`](setup.sh) — boots smolvm + nginx, drives in-guest `ab` continuously
- [`probe.d`](probe.d) — guest tcp_v4_do_rcv entry/return + per-pid
  agg + gustack.  Attaches via the BPF trampoline (FENTRY for
  `:entry`, FEXIT for `:return`).

## Why intra-guest

cross-domain-http's TSI path is the right design for benchmarking
real macOS→guest TCP — host applications connect to a guest port
without crossing the kernel TCP stack twice. But it makes
`tcp_v4_do_rcv` unreachable for that flow. This demo is the
"intra-guest" companion: same probe shape, but loopback traffic
that the guest kernel actually processes, so `@rcv_lat` fills
out and `gustack()` at TCP entry actually has data to render.

## Captured output

A real ~25 s run against ubuntu:24.04 + apt-installed nginx with
`ab -n 5000 -c 32 -k` running inside the same container.

`dtrace:::BEGIN` header (printed when the consumer comes up):

```
intra-guest HTTP trace - Ctrl-C to dump aggregations
    @reqs:    per-pid tcp_v4_do_rcv segment count.  Both nginx
              workers AND in-guest ab client threads should
              appear (loopback traffic touches both ends).
    @rcv_lat: per-segment guest TCP processing latency,
              quantize.  Tight fast-path peak vs long tail.
    gustack:  guest user stack at each fire (nginx worker /
              ab client frames).
```

Two progs JIT cleanly in the guest verifier:

```
[bifrost] prog #0: 46 insns, target='tcp_v4_do_rcv:entry', schema=5 fields (32-byte records), 2 map(s)
[bifrost] prog #1: 104 insns, target='tcp_v4_do_rcv:return', schema=5 fields (32-byte records), 2 map(s)
```

`@reqs[pid]` table at exit — one row per guest pid that touched
`tcp_v4_do_rcv` during the trace window. Each ab keepalive flow
sees ~32 inbound segments before the keepalive socket cycles, so
every pid lines up at exactly 32:

```
  @reqs
                             key         host        guest        total
                            2518            0           32           32
                            2566            0           32           32
                            2590            0           32           32
                            2533            0           32           32
                            2527            0           32           32
                            ... [~64 distinct guest pids @ 32 each] ...
                            2602            0           32           32
```

Compare to cross-domain-http where `@reqs` has counts only on
the host column (ab connect() count) and the guest column is 0
because TSI intercepts at the userspace boundary. Here it is the
opposite — the host column is 0 (no host-side ab) and the guest
column has real data.

Drops summary (always present in stderr, polled periodically and
once at exit):

```
[bifrost] dtrace summary: drops=0 (principal=0 agg=0 dyn=0 rinse=0 dirty=0 spec=0 stkstr=0 dblerr=0) errs=0
```

Per-fire `gustack()` records (after the post-agg fan-out fix —
the entry clause now compiles to 5 progs covering the agg
chain, `self->t0 = timestamp` thread-local, and `gustack()`
USTACK):

```
[bifrost] prog #0: 46 insns, target='tcp_v4_do_rcv:entry', schema=5 fields (32-byte records), 2 map(s)
[bifrost] prog #1: 60 insns, target='tcp_v4_do_rcv:entry', schema=5 fields (32-byte records), 2 map(s)
[bifrost] prog #2: 54 insns, target='tcp_v4_do_rcv:entry', schema=6 fields (536-byte records), 2 map(s)
[bifrost] prog #3: 104 insns, target='tcp_v4_do_rcv:return', schema=5 fields (32-byte records), 2 map(s)
[bifrost] prog #4: 76 insns, target='tcp_v4_do_rcv:return', schema=5 fields (32-byte records), 2 map(s)
```

Captured per-fire records (~6500 over 25 s, all from the nginx
worker pid 1714):

```
guest_kernel:tcp_v4_do_rcv:entry vmid=3 probe_id=1 gns=0xa3ad693ed gpid=1714 value=0xffffbea4e0c0
guest_kernel:tcp_v4_do_rcv:entry vmid=3 probe_id=1 gns=0xa3ad69923 gpid=1714 value=0xa3ad69923
guest_kernel:tcp_v4_do_rcv:entry vmid=3 probe_id=1 gns=0xa3ae16cc8 gpid=1714 value=0xffffbea4e0c0
... [~6500 records over 25 s, all gpid=1714 (nginx worker)] ...
```

`@rcv_lat` quantize histogram (now rendering via the SHM
AGG_PUSH path's `##xagg-guest-quantize##` markers, paired with
the libkrun-side wire-format widening — pre-fix the quantize
markers were log-only and lost in detached mode):

```
  @rcv_lat (quantize)
               value ------------- Distribution -------------       count
                 256 |                                                  0
                 512 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@         96
                1024 |@@@@@@@@@@@@@@@@@@@                              46
                2048 |@@                                                6
                4096 |@@@@                                             10
                8192 |                                                  0
               16384 |                                                  0
               32768 |                                                  2
               65536 |                                                  0
```

Real bimodal distribution: tight 512-2048 ns peak (TCP header
parse + queue fast path), long tail to 32 µs under contention.
