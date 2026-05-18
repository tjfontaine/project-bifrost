# postgres-usdt

The first end-to-end demo of the bifrost USDT provider
(`usdt:guest:<binary>:<sdt_provider>:<sdt_probe>`).  Traces postgres
at the SQL-statement level — full query latency, transaction outcomes
— rather than at the syscall level the existing `postgres-slow-query`
demo uses.

## What it shows

```
@queries:    per-pid query__start count.  postgres forks one backend
             per pgbench client; each backend pid surfaces here.
@qlat:       query__start → query__done latency, quantize().
             Captures full SQL execution including planner +
             executor + result emit — strictly more useful than the
             do_sys_openat2 distribution under steady-state pgbench
             load (cache hits make the syscall path mostly silent).
@txn:        transaction__commit / __abort counts.  Ratio surfaces
             transaction failure rate under load.
```

The bifrost source is short:

```d
usdt:guest:postgres:postgresql:query__start { @queries[pid] = count(); self->q0 = timestamp; }
usdt:guest:postgres:postgresql:query__done  / self->q0 / { @qlat = quantize(timestamp - self->q0); self->q0 = 0; }
usdt:guest:postgres:postgresql:transaction__commit { @txn["commit"] = count(); }
usdt:guest:postgres:postgresql:transaction__abort  { @txn["abort"] = count(); }
```

Four probes; one of 56 unique probe names embedded in the official
`postgres:16` Debian package's `--enable-dtrace` build.

## How USDT resolution works in bifrost

USDT support uses the **kernel-resolved** trailer pattern (same shape
as `uprobe:guest:<bin>:<sym>:entry|return` for the by-symbol path):

1. Host CLI parses `usdt:guest:postgres:postgresql:query__start` and
   stuffs `(basename="postgres", sdt_provider="postgresql",
   sdt_probe="query__start")` into the BFR7 `LOAD_PROG` trailer.
   No host-side ELF I/O, no rootfs mirror, no path candidates.
2. Guest driver finds the running task by `comm == "postgres"`,
   grabs `task->exe_file`, calls `bifrost_helper_resolve_usdt`
   (sister to `bifrost_helper_resolve_symbol` at
   `drivers/bifrost/bifrost_helpers.c`), which:
   - Reads ELF header, program headers, section headers.
   - Locates `.note.stapsdt` (`SHT_NOTE`).
   - Walks `Elf_Note` entries, matches `(provider, probe)`.
   - Translates the recorded `pc` and `semaphore` virtual
     addresses to file offsets via the covering PT_LOAD's
     `vaddr → offset` mapping.
3. Driver calls `uprobe_register(inode, pc_offset, ref_ctr_offset,
   consumer)`.  The non-zero `ref_ctr_offset` makes the kernel
   atomically increment the per-probe `unsigned short` flag in
   `.probes` on attach so the SDT body actually fires (postgres
   uses semaphore-gated probes; without the bump the `STAP_PROBE`
   macro short-circuits and the NOP at `pc` never executes).

The host-side `parse_stapsdt` helper in `host/bifrost/src/elf_syms.rs`
is kept around for offline use (e.g. a future `bifrost --list-usdt`)
and is exercised by a test against the real `postgres:16` binary, but
is **not** on the attach path.

## Wire format

`PROBE_TYPE_USDT = 9`.  Trailer (after the 36-byte BFR7 program
header):

```
[u32 bn_len][basename_bytes ≤64]
[u32 prov_len][sdt_provider_bytes ≤64]
[u32 probe_len][sdt_probe_bytes ≤256]
```

Mirrors the existing `PROBE_TYPE_UPROBE_BY_SYM` shape with an extra
provider field (provider+probe is the SDT addressing convention; a
binary may carry probes from multiple providers — `postgresql` and
`libstapsdt` for instance).

## Run

Two shells.

```sh
# shell 1 — keeps smolvm + pgbench loop running until ^C
examples/postgres-usdt/setup.sh
```

`setup.sh` prints the smolvm pid and the bifrost command.

```sh
# shell 2 — the trace itself
sudo bifrost -p $PID -s examples/postgres-usdt/probe.d
```

When you ^C the bifrost CLI it dumps aggregations.  Then ^C
`setup.sh` to tear down.

Override knobs:

```sh
PG_SCALE=10 PG_CONC=8 examples/postgres-usdt/setup.sh
```

## Why postgres:16 (Debian) rather than ubuntu/postgres or
   ubuntu:24.04 + apt-installed postgresql

The official `postgres:16` Docker image is built from the PGDG
Debian package, which ships with `--enable-dtrace`.  The binary
embeds 56 unique probe sites under provider `postgresql`.  Verify
locally with:

```sh
docker run --rm postgres:16 bash -c '
  apt-get update -qq && apt-get install -y -qq binutils
  readelf -n /usr/lib/postgresql/16/bin/postgres
' | grep -c stapsdt   # → 72 (probe sites; 56 unique names)
```

`ubuntu:24.04`'s apt-installed `postgresql` is built without
dtrace, so its `.note.stapsdt` is empty.  `ubuntu/postgres:16-24.04`
was removed from Docker Hub.

## Why /workspace/postgres rather than running from
   /usr/lib/postgresql/16/bin/postgres directly

`uprobe_register` returns `-EIO` when installed against
overlayfs-backed inodes (the standard container rootfs in crun /
smolvm).  `/workspace` is mounted as a real ext4 disk by smolvm
and supports both `exec` and `uprobe_write_opcode` COW.  The
entrypoint copies the postgres binary there at first boot and
runs it from the copy; `task->comm` becomes `"postgres"`
regardless (the kernel sets comm from `argv[0]`'s basename, not
from the path).

## Captured output

When you ^C bifrost mid-trace you'll see something like:

```
postgres USDT trace - Ctrl-C to dump
    @queries:    per-pid query__start count.  postgres forks one
                 backend per pgbench client; each backend pid
                 surfaces here.
    @qlat:       query__start -> query__done latency, quantize.
                 Captures full SQL execution including planner +
                 executor + result emit.
    @txn:        transaction__commit / __abort counts.  Ratio
                 surfaces transaction failure rate under load.

  @queries
                             key         host        guest        total
                            3478            0         3200         3200
                            3479            0         3200         3200
                            3481            0         3200         3200
                            3482            0         3200         3200

  @qlat
            value  ------------- Distribution ------------- count
              512 |                                         0
             1024 |@@@@                                     1280
             2048 |@@@@@@@@@@@@@@@@@@@@@                    6720
             4096 |@@@@@@@@@@@                              3520
             8192 |@@@                                      960
            16384 |@                                        320
            32768 |                                         0

  @txn
                             key         host        guest        total
                          commit            0         3200         3200
                           abort            0            0            0
```

(Numbers are illustrative — your `tps` will vary by hardware.)

## Files

- [`probe.d`](probe.d) — four USDT clauses + per-pid agg, latency
  quantize, txn outcome agg.  Single-shot fire (no entry/return
  pair like uprobes — USDT sites are individual NOPs).
- [`setup.sh`](setup.sh) — boots stock postgres:16 in smolvm, copies
  the binary to /workspace, drives a continuous pgbench load loop.
- [`README.md`](README.md) — this file.
