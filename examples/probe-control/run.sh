#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Three-line driver: keys mirror demo.toml.  See
# examples/_common/README.md for the harness contract.

set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
DEMO_NAME="probe-control"
DEMO_SCRIPT="probe.d"
DEMO_WORKLOAD="auto"
RUNTIME_SECONDS=16
EXPECT_RECORDS=0
EXPECT_AGG_ROWS=1
export DEMO_DIR DEMO_NAME DEMO_SCRIPT DEMO_WORKLOAD \
       RUNTIME_SECONDS EXPECT_RECORDS EXPECT_AGG_ROWS

# shellcheck source=../_common/run-demo.sh
. "$DEMO_DIR/../_common/run-demo.sh"
demo_run
