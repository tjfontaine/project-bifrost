#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Three-line driver: keys mirror demo.toml.  See
# examples/_common/README.md for the harness contract.

set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
DEMO_NAME="redis-uprobe"
DEMO_SCRIPT="probe.d"
DEMO_WORKLOAD="auto"        # setup.sh drives the redis-cli PING loop
RUNTIME_SECONDS=16
EXPECT_RECORDS=100
EXPECT_AGG_ROWS=1
AGG_NAMES="@cmds @cmd_lat"
BIFROST_HOST_RESOLVE_UPROBE=1
BIFROST_ROOTFS="${BIFROST_ROOTFS:-/tmp/bifrost-redis-rootfs}"
export DEMO_DIR DEMO_NAME DEMO_SCRIPT DEMO_WORKLOAD \
       RUNTIME_SECONDS EXPECT_RECORDS EXPECT_AGG_ROWS AGG_NAMES \
       BIFROST_HOST_RESOLVE_UPROBE BIFROST_ROOTFS

# shellcheck source=../_common/run-demo.sh
. "$DEMO_DIR/../_common/run-demo.sh"
demo_run
