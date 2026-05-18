#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# check-crate-graph.sh — keep libkrun from depending on the full host crate.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVICES="$ROOT/third_party/smolvm/libkrun/src/devices"
fail=0

echo "[check-crate-graph] libkrun dependency audit"

if grep -R -n 'package = "bifrost"' "$DEVICES/Cargo.toml"; then
    echo "[crate-graph] krun-devices depends on the full host bifrost crate" >&2
    fail=1
fi

if grep -R -n 'dif_lower::' "$DEVICES/src/virtio/conduit" "$ROOT/host/virtio-conduit/src"; then
    echo "[crate-graph] krun-devices still imports the old dif_lower alias" >&2
    fail=1
fi

if ! grep -q 'krun-virtio-conduit' "$DEVICES/Cargo.toml"; then
    echo "[crate-graph] krun-devices is missing the generic virtio-conduit dependency" >&2
    fail=1
fi

if [[ $fail -eq 0 ]]; then
    echo "[check-crate-graph] OK: krun-devices uses the generic virtio-conduit crate only"
fi

exit "$fail"
