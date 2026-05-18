# failed-opens

System-wide failed-open profile.  Demonstrates `retval` — the
function's return value — in a fbt `:return` clause, with a
predicate that filters on negative retval (errno) and a multi-key
aggregation joining `(execname, retval)` tuples.

## What it shows

`retval` lowers to the fexit context's `args[<arity>]` slot — the
slot the BPF trampoline writes the function's return value into
on FEXIT.  The host CLI looks up the target's parameter count via
vmlinux BTF; for `do_sys_openat2` (3 args), `retval` substitutes
to `arg3`, which the existing `arg0..arg9` DIF lowering reads as
`ctx[24]`.

Under the failed-open mix in `setup.sh`, `@errs[execname, retval]`
typically surfaces:

| execname | retval | meaning |
|---|---:|---|
| `cat`  | -2  | ENOENT — `/etc/missing-NNNN` doesn't exist |
| `cat`  | -13 | EACCES — alice can't read `/etc/shadow` |

Plus background noise from systemd / login / etc. doing their own
opens that occasionally fail.

## Run

Two shells.

```sh
# shell 1 — boots smolvm + drives the failed-open mix
examples/failed-opens/setup.sh
```

`setup.sh` prints the smolvm pid and the bifrost command to use.

```sh
# shell 2 — the trace itself
sudo bifrost -p $PID -s examples/failed-opens/probe.d
```

## Files

- [`setup.sh`](setup.sh) — boots smolvm + drives a mixed
  failed-open workload (ENOENT from random missing files,
  EACCES from `alice → /etc/shadow`)
- [`probe.d`](probe.d) — `fbt:guest:do_sys_openat2:return /retval < 0/`
  with a multi-key `@errs[execname, retval]` aggregation

## Why this demo exists

`retval` is one of the canonical DTrace-fbt-return primitives, and
a brand-new addition to bifrost's lowering as of the
fbt-canonicalization landing.  Before this demo, no probe
exercised the rewrite path — without it the lowering was tested
only by parser unit tests.  This demo closes that gap with the
shape DTrace users reach for first: error-path tracing across the
system.
