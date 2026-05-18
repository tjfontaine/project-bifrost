# cross-domain-http

HTTP workload demo for the cross-domain Bifrost path. `setup.sh`
boots the `bifrost-bench` image, starts nginx, and drives `ab`
inside the same guest container. Keeping the client and server in
one guest network namespace makes the guest TCP receive path
observable: `tcp_v4_do_rcv` fires under real benchmark load.

Earlier versions drove macOS `ab` through smolvm's TSI
port-forward and tried to combine a host `syscall::connect`
aggregation with guest TCP probes. That is not a valid automated
demo for the current runtime: host `ab` is outside the libdtrace
target pid, and TSI does not traverse the guest TCP stack.

## What It Shows

- `@reqs[pid] = count()` on `fbt:guest:tcp_v4_do_rcv:entry`.
- `@rcv_lat = quantize(...)` across FENTRY/FEXIT on
  `tcp_v4_do_rcv`.
- `xstack(SAMPLE, 32)` to exercise the sampled cross-stack wire
  path while HTTP load is running.

## Run

```sh
examples/cross-domain-http/run.sh
```

For the two-shell shape:

```sh
examples/cross-domain-http/setup.sh
sudo bifrost -p $PID -s examples/cross-domain-http/probe.d
```

Useful setup knobs:

```sh
AB_REQS=20000 AB_CONC=128 examples/cross-domain-http/setup.sh
IMAGE=localhost:5005/bifrost-bench:latest examples/cross-domain-http/setup.sh
```

## Files

- `setup.sh` boots smolvm and owns the in-guest nginx/ab loop.
- `probe.d` traces guest TCP receive, latency, and sampled xstack.
- `run.sh` uses the shared demo harness and expects both records
  and aggregation rows.

## Why This Differs From Host-Port HTTP

Host-to-guest HTTP over TSI is still a useful system behavior, but
it is not the right signal for this demo. TSI accepts host TCP at
the libkrun boundary and moves data over the guest transport without
lighting up `tcp_v4_do_rcv`. Use this demo for live guest TCP
probes; use the TSI notes in the top-level README for the remaining
host-port data-leg limitation.
