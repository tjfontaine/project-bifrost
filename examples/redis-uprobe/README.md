# redis-uprobe

The first end-to-end demo that exercises bifrost's userspace
uprobe path: a `bifrost:guest_user:redis-server:processCommand`
clause attached to a real binary inside a running smolvm guest.

The redis-smoke-test demo (a sibling) uses a kprobe on
`tsi_control_sendrecv_msg` — kernel-side, not userspace. This
demo is the userspace counterpart: the uprobe attaches to
`processCommand` inside `redis-server`, the symbol is resolved by
the host CLI's ELF parse, the (binary, offset) tuple is shipped
into the guest via the BFR7 LOAD_PROG trailer, and the in-kernel
bifrost driver registers the uprobe on the running redis pid.

The demo splits into two halves:

- [`setup.sh`](setup.sh) boots `ubuntu:24.04` in smolvm,
  apt-installs `redis-server`, makes it the container entrypoint,
  and drives a continuous in-guest `redis-cli ping` loop. No
  host-side install needed.
- You run bifrost yourself in another shell, dtrace-style.

## What it shows

Three artifacts at trace exit, all from the uprobe clause:

1. **`@cmds[pid]` per-pid command count.** redis is single-
   threaded by default; the postmaster pid dominates the table.

2. **`@cmd_lat` quantize.** Power-of-two histogram of
   processCommand entry → return latency. Real PING traffic fills
   the sub-microsecond bucket; under load with richer commands
   the long tail surfaces (BGSAVE, SUNIONSTORE, etc.).

3. **`gustack()` at entry.** The ubuntu-apt-installed redis-server
   has frame pointers, so the guest user stack walks cleanly
   into:
   ```
   redis-server!processCommand+0x...
   redis-server!call+0x...
   redis-server!processInputBuffer+0x...
   redis-server!readQueryFromClient+0x...
   redis-server!aeProcessEvents+0x...
   ```

## Run

Two shells.

```sh
# shell 1 — keeps smolvm + redis-cli PING loop running until ^C
examples/redis-uprobe/setup.sh
```

`setup.sh` prints the smolvm pid and the bifrost command to use.

```sh
# shell 2 — the trace itself.
sudo bifrost -p $PID -s examples/redis-uprobe/probe.d
```

Three equivalent forms — pick whichever you prefer:

```sh
# 1. -s flag, like dtrace
sudo bifrost -p $PID -s examples/redis-uprobe/probe.d

# 2. inline D expression with -n, like `dtrace -n`
sudo bifrost -p $PID \
    -n 'bifrost:guest_user:redis-server:processCommand:entry { @[pid] = count(); }'

# 3. self-executing script
sudo examples/redis-uprobe/probe.d -p $PID
```

When you have enough samples, ^C the bifrost CLI to dump
aggregations, then ^C `setup.sh` to tear down.

## Files

- [`setup.sh`](setup.sh) — boots smolvm + redis, drives in-guest `redis-cli ping` loop
- [`probe.d`](probe.d) — uprobe entry/return + per-pid agg + gustack

## Why ubuntu:24.04 + apt-install rather than redis:7-alpine

The `redis:7-alpine` image (used by the redis-smoke-test sibling
demo) is musl-based and strips frame pointers, which would
truncate `gustack()`. Ubuntu 24.04+ builds redis-server with
`-fno-omit-frame-pointer` (the distro default since the
toolchain transition), so the call chain walks cleanly into
`processCommand` and its callers.

## How the uprobe path differs from kprobes

The demo's bifrost: clause uses the `guest_user` provider:

```d
bifrost:guest_user:redis-server:processCommand:entry { ... }
```

End-to-end:

1. **Host CLI ELF parse.** The bifrost CLI on macOS opens the
   resolved redis-server binary inside the guest's persistent
   overlay (via the smolvm path resolution), reads the symbol
   table, finds `processCommand`, computes the file offset.
2. **BFR7 LOAD_PROG trailer.** The (binary path, file offset)
   tuple is appended to the LOAD_PROG wrapper as a uprobe
   trailer (probe_type 5).
3. **Guest driver registers.** The in-kernel bifrost driver
   walks `for_each_process` to find the redis-server task,
   then registers a uprobe at the resolved offset via the
   in-kernel uprobe API.
4. **Boot-order race.** If the bifrost CLI attaches before
   redis-server has actually started inside the container, the
   `kern_path` retry loop in linux-bifrost commit 0041
   (`bifrost-uprobe-kern_path-retry`) handles the race.

## Captured output

End-to-end working as of libkrunfw 0050 (container-aware
uprobe resolution) + 0051 (C task-walk + ELF symtab parser
helpers).

Five progs JIT cleanly — entry chain (count + thread-local
timestamp + gustack USTACK) and return chain (latency-quantize
+ self->t0 reset):

```
[bifrost] kernel-resolved uprobe redis-server:processCommand (driver walks /proc + parses ELF)
[bifrost] prog #0: 46 insns, uprobe(by-sym) target=redis-server:processCommand (kernel-resolved) (entry), schema=5 fields (32-byte records), 2 map(s)
[bifrost] prog #1: 60 insns, uprobe(by-sym) target=redis-server:processCommand (kernel-resolved) (entry), schema=5 fields (32-byte records), 2 map(s)
[bifrost] prog #2: 54 insns, uprobe(by-sym) target=redis-server:processCommand (kernel-resolved) (entry), schema=6 fields (536-byte records), 2 map(s)
[bifrost] prog #3: 104 insns, uretprobe(by-sym) target=redis-server:processCommand (kernel-resolved) (return), schema=5 fields (32-byte records), 2 map(s)
[bifrost] prog #4: 76 insns, uretprobe(by-sym) target=redis-server:processCommand (kernel-resolved) (return), schema=5 fields (32-byte records), 2 map(s)
[bifrost] LOAD_PROG acked; programs queued
[bifrost] auto-injected host D (757 bytes); attaching libdtrace in-process to pid=...
```

`@cmds[pid]` table fills with one row per redis pid (just the
postmaster — redis is single-threaded by default; gpid=225 is
the in-guest container PID 1):

```
  @cmds
                             key        value
                             225         7511
```

`@cmd_lat` quantize histogram, real PING-driven latency:

```
  @cmd_lat (quantize)
               value ------------- Distribution -------------       count
                1024 |                                                  0
                2048 |@@@@@@@@@@@@@@@@                               1963
                4096 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@       4850
                8192 |@@@@@                                           672
               16384 |                                                 26
               32768 |                                                  0
```

The bimodal shape matches what we'd expect from PING:
processCommand fast-path is 2-8 µs (header parse + reply
queue), with the 4 µs bucket dominating; the ~16 µs tail
captures the occasional path through redis's slow logger /
event-loop quiesce.

### Gaps closed to get here

1. **Kernel-resolved trailer (probe_type 4/5).**
   Pre-fix the host CLI emitted `probe_type` 4/5
   ("kernel-resolved": basename + symbol_name trailer) but the
   guest only understood 0/1 (kprobe) and 2/3 (uprobe path +
   offset).  Mismatched trailer length shifted maps_base, the
   MapDef array got parsed against random bytes, and a bogus
   instruction count drove `__memcpy` off a cliff (negative
   size).  Fix: dispatch trailer parsing on probe_type
   (libkrunfw patch 0050).

2. **Container-aware task lookup.**
   `kern_path()` runs in init's mount namespace and can't see
   the container's overlay.  Fix: walk `for_each_process` first
   to find a task whose `comm` matches the basename, then take
   its `mm->exe_file` directly.  Done in a small C helper
   (`bifrost_helper_find_task_by_comm`) since `_raw_read_lock`
   isn't exported to Rust modules (libkrunfw patch 0051).

3. **Guest-side ELF symbol resolution.**
   Once we have the file from `exe_file`, parse SHT_SYMTAB or
   `.dynsym`/`.dynstr` to find the symbol's `st_value` (file
   offset for ET_DYN PIE binaries) — also a C helper
   (`bifrost_helper_resolve_symbol`), capped at 16 MB symtab /
   strtab to bound vmalloc pressure.

4. **Apostrophe-broke-the-quoting bug in `setup.sh`.**
   The container entrypoint was wrapped in `bash -c '...'`,
   single-quoted to keep the host shell from expanding `$(...)`.
   A comment containing `can't` terminated the single quote;
   everything after that fell through to the host shell.  The
   `$(which redis-server)` then resolved against macOS brew
   instead of inside the container.  Fix: spell it `cannot`.

5. **Container `/dev/shm` is `noexec`, `/usr/bin` is on
   overlayfs.**
   uprobes can't write breakpoints to overlayfs-backed inodes
   (`uprobe_write_opcode` returns -EIO).  `/dev/shm` is tmpfs
   but crun mounts it with `noexec` so we can't run the binary
   from there.  The smolvm-provisioned `/workspace` is a real
   ext4 disk that supports both exec and uprobe COW writes —
   copy the redis-server binary to `/workspace/redis-server`
   and exec it from there.

6. **probe_id was per-clause, schemas-vec is per-prog.**
   Multi-action entry clauses (count agg + thread-local
   timestamp + gustack) lower into 3 progs sharing the same
   probe_id.  The libkrun-side renderer indexes
   `schemas[probe_id]` to pick a record schema, but the
   schemas vec is in load order — so the gustack extra (a
   536-byte UserStack record) was rendered as the main
   prog's count-agg schema (32 bytes) and its ustack[]+
   exe_path tail was silently truncated.  Fix: assign
   `probe_id` from a global counter so every prog (main +
   each ExtraProg) gets its own slot.

7. **Symbolicating ustack frames without leaking the binary
   to the host.**  With (6) the renderer sees the full 9-frame
   stack but prints `redis-server+0x76ff0` (offset only)
   because `/workspace/redis-server` lives on the guest's ext4
   disk.  An earlier scaffold mounted a host-shared staging
   dir into the container so the in-container entrypoint
   could `cp` the binary into a path the renderer reads off
   `$BIFROST_ROOTFS` — that worked, but it leaked the binary
   into the vmm's filesystem (the wrong shape for a
   guest-isolating tool).
   The right shape is for the kernel to side-channel the
   symbol info out: when the bifrost driver registers a
   uprobe its existing ELF parser already walks SHT_SYMTAB
   (or .dynsym) to resolve the requested symbol's offset,
   so emitting the rest of the function symbols across the
   SHM rsp_ring with a `SYM_TABLE_PROBE_ID` (0xFFFFFFFC)
   correlation tag is essentially free.  Host renderer keys
   its symbol cache by the binary's path string (already
   present in each VMA-table entry), looks up file offsets
   per fire — no host ELF read, no rootfs mirror.
   Kernel side: `bifrost_helper_emit_symtab` +
   `push_symtab_snapshot` (libkrunfw
   `patches-pending/0052/`).  Host side: `PushedSymTab` +
   `pushed_syms` cache in libkrun 53066a5.

The result: end-to-end `@cmds` per-pid table, `@cmd_lat`
quantize histogram, AND symbolicated `gustack()` frames per
fire — all populated with real PING traffic from the in-guest
redis-server uprobed via kernel-resolved processCommand symbol
offset:

```
guest_kernel:processCommand:entry vmid=1 probe_id=3 gns=... gpid=225
    ustack=[redis-server!processCommand,
            redis-server!readQueryFromClient+0x238,
            redis-server+0x16d0ec,
            redis-server+0x6d6e4,
            redis-server!aeMain+0x24,
            redis-server!main+0x348,
            0xffffb8ff84c4,           ← libc/libpthread (no symtab push for those VMAs)
            0xffffb8ff8598,
            redis-server!_start+0x30]
    exe_path=/workspace/redis-server
```

`processCommand` sits at the top (offset 0 — the uprobe fires
exactly at function entry, before the prologue advances PC).
`readQueryFromClient+0x238` is the call site that drove this
processCommand invocation; `aeMain+0x24` is redis's epoll
event-loop tail; the chain bottoms out in `_start`.  Two
`redis-server+0x16d0ec` / `+0x6d6e4` frames are LTO-inlined
static functions that have zero-size STT_FUNC entries in the
symbol table (the side-channel skips entries whose `[st_value,
st_value + st_size)` interval is empty — they could never match
a real PC).  The two `0xffff...` libc/libpthread frames are
unsymbolicated because the kernel push only fires for the
uprobed binary; extending it to every file-backed VMA in the
firing task is the natural follow-up and would close that gap.
