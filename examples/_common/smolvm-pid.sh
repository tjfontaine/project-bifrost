#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Print the pid of the currently running smolvm machine.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SMOLVM="${SMOLVM:-$PROJECT_ROOT/third_party/smolvm/target/release/smolvm}"

pid=$(pgrep -n -f 'smolvm.*/target/release/smolvm machine run' 2>/dev/null \
    || pgrep -n -f '_boot-vm.*boot-config' 2>/dev/null \
    || true)
if [ -n "$pid" ]; then
    printf "%s\n" "$pid"
    exit 0
fi

status=$("$SMOLVM" machine status 2>/dev/null || true)
pid=$(printf "%s\n" "$status" | sed -n 's/.*PID: \([0-9][0-9]*\).*/\1/p' | head -1)
if [ -n "$pid" ]; then
    printf "%s\n" "$pid"
    exit 0
fi

pgrep -f '_boot-vm.*boot-config' | tail -1
