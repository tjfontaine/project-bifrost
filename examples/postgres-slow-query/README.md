# postgres-slow-query

Postgres I/O analysis under sustained pgbench load: which
function is opening which file, how long does each open take,
and which backend is busiest?

The demo splits into two halves:

- [`setup.sh`](setup.sh) boots `ubuntu/postgres` in smolvm,
  initialises a pgbench dataset (scale=5, ~75 MB), and drives a
  continuous pgbench client loop against it. It does not run
  bifrost. pgbench runs **inside the guest** via
  `smolvm machine exec`, so no host-side libpq install is
  required.
- You run bifrost yourself in another shell, dtrace-style.

## What it shows

A combined clause on `do_sys_openat2:entry` filters on
`execname == "postgres"`, captures `gustack()`, stores an entry
timestamp; the paired `:return` clause feeds open latency into a
`quantize()`. A second clause aggregates opens by backend pid.

When you ^C bifrost:

- `@open_lat` — power-of-two histogram of open latency under
  load. Real pgbench traffic fills out a distribution including
  the dcache-hit fast peak and the WAL-fsync / index-page-fault
  long tail.
- `@opens[pid]` — per-backend open counts; postgres forks one
  backend per pgbench client, so this surfaces which backends
  did the most I/O.
- per-fire `gustack()` — postgres function chain at each open
  (e.g., `mdread → ReadBuffer_common → heap_getnextslot → ExecScan`).

The string-compare predicate (`execname == "postgres"`) lowers
to the eBPF `bpf_strncmp` helper. Combining the timestamp store
with `gustack()` in one clause exercises the multi-action schema
selection in the bifrost lowering pipeline.

## Run

Two shells.

```sh
# shell 1 — keeps smolvm + pgbench loop running until ^C
examples/postgres-slow-query/setup.sh
```

`setup.sh` prints the smolvm pid and the bifrost command to use.

```sh
# shell 2 — the trace itself.
# (assumes host/runtime/ is on PATH; see top-level README)
sudo bifrost -p $PID -s examples/postgres-slow-query/probe.d
```

Three equivalent forms — pick whichever you prefer:

```sh
# 1. -s flag, like dtrace
sudo bifrost -p $PID -s examples/postgres-slow-query/probe.d

# 2. inline D expression with -n, like `dtrace -n`
sudo bifrost -p $PID \
    -n 'bifrost::do_sys_openat2:entry / execname == "postgres" / { @[pid] = count(); }'

# 3. self-executing script (probe.d has #!/usr/bin/env bifrost)
sudo examples/postgres-slow-query/probe.d -p $PID
```

When you have enough samples, ^C the bifrost CLI to dump
aggregations, then ^C `setup.sh` to tear down.

Override knobs on `setup.sh`:

```sh
PG_SCALE=10 PG_CONC=8 examples/postgres-slow-query/setup.sh
```

## Files

- [`setup.sh`](setup.sh) — boots smolvm + postgres, runs `pgbench -i`, drives a continuous pgbench client loop
- [`probe.d`](probe.d) — entry/return clauses + per-backend agg.
  Attaches via the BPF trampoline (FENTRY for `:entry`, FEXIT
  for `:return`).  `@open_lat` reads only `timestamp -
  self->t0`, not the function's return value, so existing DIF
  lowering covers it on FEXIT.

## Why Ubuntu postgres

`gustack()` is a frame-pointer walk. The official
`ubuntu/postgres:16-24.04_beta` image is built with
`-fno-omit-frame-pointer`, so the user stack walks cleanly into
PostgreSQL functions like `ExecScan`, `heap_open`, and
`index_open`. The Debian-based `postgres:16` image strips frame
pointers and would produce truncated stacks.

## Captured output

A real 25 s `probe.d` run against a fresh smolvm during sustained
`pgbench -c 4` load. ~1.46M per-fire records flowed through the
SHM RECORD_PUSH channel; the on-exit `@opens` xagg table picks
out the busiest postgres backends.

`dtrace:::BEGIN` header (printed when the consumer comes up;
appears in stdout interleaved with the per-fire stream because
the printf sink and the SHM RECORD_PUSH path both write to
stdout):

```
postgres I/O trace - Ctrl-C to dump aggregations
    @opens:    per-pid postgres backend file-open counts under pgbench
               load. The postmaster pid does the bulk (every backend
               fork, every WAL segment, every shared-buffer mapping);
               each pgbench worker backend gets its own row.
    @open_lat: bucketed open latency. Long tail = WAL fsync /
               index page fault. Tight peak = dcache hit.
    gustack:   postgres function chain at each open (frame-pointer
               build walks cleanly into ExecScan, mdread, etc.)
```

Per-fire stream — `do_sys_openat2` records from the postgres
backends (gpid 214 is the postmaster running as "postgres" inside
the persistent overlay; the `value` column is the gustack frame
pointer captured by the predicate-filtered clause):

```
guest_kernel:do_sys_openat2:entry vmid=0 probe_id=1 gns=0x5a149f014 gpid=214 value=0x3bc940
guest_kernel:do_sys_openat2:entry vmid=0 probe_id=1 gns=0x5a149f51f gpid=214 value=0x5a149f573
guest_kernel:do_sys_openat2:entry vmid=0 probe_id=1 gns=0x5a14a2811 gpid=214 value=0x3bc940
guest_kernel:do_sys_openat2:entry vmid=0 probe_id=1 gns=0x5a14a2f64 gpid=214 value=0x5a14a2f64
... [~1,464,000 records over 25 s, 0 RECORD_PUSH drops] ...
```

`@opens[pid]` table at exit — per-backend file-open counts. The
postmaster (pid 214) does the bulk (645k — every backend fork,
every shared-buffer mapping, every WAL segment open). Each
pgbench-driven worker backend pid does ~60-68 opens per
transaction batch:

```
  @opens
                             key         host        guest        total
                             214            0       645600       645600
                            3456            0           68           68
                            3483            0           68           68
                            3519            0           68           68
                            3474            0           68           68
                            3501            0           68           68
                            3447            0           68           68
                            3510            0           68           68
                            3465            0           68           68
                            3492            0           68           68
                            3502            0           60           60
                            3457            0           60           60
                            3511            0           60           60
```

(`host` is 0 throughout because no host-side clause writes to
`@opens` in this script — the agg is guest-only. The xagg join
reuses the same renderer as `cross-domain-http`'s shared agg.
Single-key by pid because the predicate already pins
execname="postgres" — the multi-key form `[execname, pid]` does
work end-to-end now (libkrun-side `render_key` chunks 8 bytes at
a time and the host-side cross-domain rewriter emits a matching
`"<execname>",<pid>` marker), it would just be redundant under
this predicate.)

Per-fire `gustack()` — postgres function chain at each open. With
frame pointers (Ubuntu apt-installed `postgresql`), the stack
walks cleanly into `ExecScan`, `heap_getnextslot`, `mdread`,
`ReadBuffer_common`, etc. The `value` column in the per-fire
stream is the top user-stack frame at fire time.

Drops summary (always present in stderr):

```
[bifrost] dtrace summary: drops=0 (principal=0 agg=0 dyn=0 rinse=0 dirty=0 spec=0 stkstr=0 dblerr=0) errs=0
[bifrost] detached cleanly (reap queued programs)
```

Setup caveat: `setup.sh` apt-installs postgresql + postgresql-
contrib into the guest's persistent overlay on first run (~90 s),
then runs `pgbench -i -s 5` (~30 s) to populate the bench
dataset. Subsequent runs reuse the overlay and start in seconds.
The image is `ubuntu:24.04` (apt-installed postgres) rather than
the official `ubuntu/postgres:16-24.04_beta` — that tag was
removed from Docker Hub and now returns MANIFEST_UNKNOWN.
