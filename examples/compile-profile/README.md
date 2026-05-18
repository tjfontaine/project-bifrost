# compile-profile

Anatomy of a real C compile, viewed from macOS: every file open
by every toolchain subprocess (gcc / cc1 / as), grouped and
quantized, while a small include-heavy C translation unit is compiled in a tight loop inside the guest.

The demo splits into two halves:

- [`setup.sh`](setup.sh) boots the local `bifrost-bench` image in smolvm, installs `build-essential` if needed, then runs `gcc -c profile.c` in a continuous loop. It does not run bifrost. No port-forward needed — the workload runs entirely inside the guest entrypoint.
- You run bifrost yourself in another shell, dtrace-style.

## What it shows

The probe attaches three clauses on `do_sys_openat2`:

- `@by_tool[execname]` and `@by_pid[execname, pid]` —
  multi-key aggregation showing which tool and which fork did the
  most opens.
- A combined-clause cc1 filter (`execname == "cc1"`) stores entry
  timestamp and captures `gustack()` for the cc1 function chain.
- The matching `:return` clause feeds `quantize(timestamp - t0)`
  into `@open_lat`.

You can see the include-search-path traversal, the assembler
opening intermediates from `/tmp`, and how a single translation unit pulls in repeated system-header opens.

## Run

Two shells.

```sh
# shell 1 — keeps smolvm + gcc loop running until ^C
examples/compile-profile/setup.sh
```

`setup.sh` prints the smolvm pid and the bifrost command to use.

```sh
# shell 2 — the trace itself.
# (assumes host/runtime/ is on PATH; see top-level README)
sudo bifrost -p $PID -s examples/compile-profile/probe.d
```

Three equivalent forms — pick whichever you prefer:

```sh
# 1. -s flag, like dtrace
sudo bifrost -p $PID -s examples/compile-profile/probe.d

# 2. inline D expression with -n, like `dtrace -n`
sudo bifrost -p $PID \
    -n 'bifrost::do_sys_openat2:entry { @[execname] = count(); }'

# 3. self-executing script (probe.d has #!/usr/bin/env bifrost)
sudo examples/compile-profile/probe.d -p $PID
```

When you have enough samples, ^C the bifrost CLI to dump
aggregations, then ^C `setup.sh` to tear down.

The first run may pay an apt-install cost; subsequent runs reuse the cached overlay and start compiling immediately.

## Files

- [`setup.sh`](setup.sh) — boots smolvm + ubuntu, runs a continuous gcc compile loop
- [`probe.d`](probe.d) — multi-key agg + filtered combined clause
  + return-side quantize.  Attaches via the BPF trampoline
  (FENTRY for `:entry`, FEXIT for `:return`).
- [`probe-stream.d`](probe-stream.d) — non-aggregating per-fire `printf("openat execname=%s pid=%d\n", execname, pid)` variant; useful for measuring raw record-stream throughput across the bifrost pipeline (see throughput numbers below)

## Why Ubuntu 24.04

Ubuntu 24.04+ builds the toolchain itself with
`-fno-omit-frame-pointer`, so the cc1 stack walks cleanly into
the C frontend without bottoming out in opaque libc frames.

## Captured output

A real ~25 s `probe.d` run against a fresh smolvm during the gcc
compile loop. The 4-clause wrapper compiles to 4 progs (the count
agg, the cc1-filtered combined clause, the cc1 gustack emit, and
the `:return` quantize) and attaches at `do_sys_openat2`.

`dtrace:::BEGIN` header is printed when the consumer comes up
(buried in the per-fire stream that starts immediately because
both write to stdout):

```
compile profile - Ctrl-C to dump aggregations
    @by_tool:  file-open counts per toolchain subprocess (cc1, gcc, as, ld, ...)
    @by_pid:   per-(execname, pid) breakdown - see fork fan-out
    @open_lat: cc1 open latency quantize - first-include slow path vs dcache hits
    gustack:   guest user stack at each cc1 open
```

Per-fire stream (`probe_id=2` is the cc1 gustack emit clause; the
`value` field is the gustack-frame pointer for `gustack()`):

```
guest_kernel:do_sys_openat2:entry vmid=0 probe_id=2 gns=0x64dfd8549 gpid=250 value=0xffffa7f0d30c
guest_kernel:do_sys_openat2:entry vmid=0 probe_id=2 gns=0x64dfd8c1f gpid=250 value=0x64dfd8c49
guest_kernel:do_sys_openat2:entry vmid=0 probe_id=2 gns=0x64dfdea5c gpid=250 value=0xffffa7f0d30c
guest_kernel:do_sys_openat2:entry vmid=0 probe_id=2 gns=0x64dfdf350 gpid=250 value=0x64dfdf350
... [9092 records over 25 s, all gpid matching cc1 pids] ...
```

`@by_tool` aggregation, dumped live every 2 s and on shutdown
(quoted execnames thanks to the agg-key `execname` lowering — the
8-byte slot covers everything in this demo):

```
  @by_tool
                             key         host        guest        total
                          "init"            0         3228         3228
                           "cc1"            0         1086         1086
                          "crun"            0          194          194
                            "as"            0           18           18
                          "bash"            0           14           14
                           "gcc"            0            6            6
```

Numbers are honest: `init` (PID 1, the agent inside the container)
opens a lot of files via the runc shim setup; `cc1` opens ~1086
times across the compile loop (every header in `<stdint.h>`,
`<string.h>`, etc. expanded); `as` opens fewer (assembler reads
intermediates). `crun` is the OCI runtime invoked once per
the container entrypoint.

`@by_pid[execname, pid]` now lowers to its own BPF program (the
multi-agg fan-out fix) and the map fills correctly on the guest
side, but does NOT yet render in the host CLI's xagg table.  The
guest→host AGG_SNAPSHOT wire format is fixed-shape
`[i32 fake_fd][u64 key][u64 value]` per row, so multi-key
composites get truncated to their first 8 bytes (the execname
portion); the pid is lost on the boundary.  The fix is to widen
the wire format to a length-prefixed key — paired libkrun rebuild
required.  Until that lands, `@by_pid`'s data lives in the guest
BPF map but is invisible from the bifrost CLI.

`probe-stream.d` (the non-aggregating variant) emits one printf
per fire with the `execname` resolved to its full
`task->comm` bytes via the 16-byte string-slot lowering:

```
guest_kernel:do_sys_openat2:entry vmid=0 probe_id=1 gns=0x… gpid=250 :: openat execname=cc1 pid=250
guest_kernel:do_sys_openat2:entry vmid=0 probe_id=1 gns=0x… gpid=213 :: openat execname=init pid=213
guest_kernel:do_sys_openat2:entry vmid=0 probe_id=1 gns=0x… gpid=265 :: openat execname=as pid=265
... [~9000 lines / 25 s sustained, zero drops on the SHM
RECORD_PUSH path]
```

Shutdown footer (always present in stderr regardless of probe
shape):

```
[bifrost] dtrace summary: drops=0 (principal=0 agg=0 dyn=0 rinse=0 dirty=0 spec=0 stkstr=0 dblerr=0) errs=0
[bifrost] consumer thread shutdown complete
[bifrost] detached cleanly (reap queued programs)
```
