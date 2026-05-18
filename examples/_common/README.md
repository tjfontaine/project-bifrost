# `examples/_common` — shared demo harness

The demo harness lifts the boot → trace → assert → cleanup loop out
of every demo's `setup.sh` into a single sourceable bash library. Each
demo becomes a thin
declarative spec (`demo.toml`) plus a three-line driver
(`run.sh`).

## Files

- `run-demo.sh` — sourceable library exposing `demo_run`.
  Boots the demo's setup script, waits for the ready banner,
  runs `host/runtime/bifrost-trace.sh` for `RUNTIME_SECONDS`,
  parses output, and asserts `drops=0` plus the configured
  record / agg-row floors.
- `cleanup-trap.sh` — idempotent EXIT/INT/TERM cleanup hook.
  Calls `sudo -n host/runtime/cleanup.sh`, then `pkill -KILL -f
  "examples/.*setup.sh"`, then `pkill -P $$`.

## `demo.toml` keys

| key                | meaning                                                                                                     |
|--------------------|-------------------------------------------------------------------------------------------------------------|
| `script`           | probe-D source under the demo dir (default: `probe.d`)                                                      |
| `workload`         | `auto` if `setup.sh` already drives traffic; `external <cmd>` if the harness must spawn a workload itself   |
| `runtime_seconds`  | trace duration before the harness sends SIGINT (default: 16)                                                |
| `expect_records`   | minimum per-fire records the trace must produce (lines containing `probe_id=` on stdout)                    |
| `expect_agg_rows`  | minimum total rows across all `@<name>` aggregations (lines under an indented `  @<name>` header on stderr) |
| `agg_names`        | advisory list of expected aggregation names; used for documentation today, may gate per-name in the future  |
| `description`      | one-line summary, surfaced in CI / docs                                                                     |

The harness does NOT parse `demo.toml` directly — TOML support in
bash would mean another tool dep.  Instead, each demo's `run.sh`
re-states the values as environment variables.  Keep them in sync.

## Adding a new demo

1. Drop a `probe.d` and a `setup.sh` that prints `[setup] ready.`
   when the VM has booted and traffic is flowing.
2. Add `demo.toml` (informational; mirror what your `run.sh`
   exports).
3. Add a three-line `run.sh`:
   ```sh
   #!/usr/bin/env bash
   set -euo pipefail
   DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
   DEMO_NAME="my-demo"
   RUNTIME_SECONDS=20
   EXPECT_RECORDS=50
   EXPECT_AGG_ROWS=1
   export DEMO_DIR DEMO_NAME RUNTIME_SECONDS EXPECT_RECORDS EXPECT_AGG_ROWS
   . "$DEMO_DIR/../_common/run-demo.sh"
   demo_run
   ```
4. Run `examples/my-demo/run.sh`.  PASS exits 0; any failure
   prints `[demo-harness] FAIL my-demo: <reason>` and exits 1.

## Cleanup invariant

`demo_cleanup` runs on EXIT, INT, and TERM, even on `kill -INT`
of the harness mid-trace.  It is idempotent — safe to run twice.
NOPASSWD-compatible: only `sudo -n host/runtime/cleanup.sh` and
`sudo -n host/runtime/bifrost-trace.sh ...` are invoked, both
covered by the `host/*/*` sudoers wildcard.
