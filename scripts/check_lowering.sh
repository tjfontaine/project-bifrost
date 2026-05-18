#!/bin/bash
# Run the bifrost lowering pipeline against every demo D script in
# host/runtime/ and assert each produces a wrapper that passes the
# host-side static verifier. Catches lowering regressions without
# needing to boot a guest VM.
#
# Why a shell script rather than `cargo test`: the lowering's
# entry point (libdtrace's `dtrace_open`) requires DTrace privilege,
# which `cargo test` doesn't have without an awkward sudo wrap. The
# bifrost CLI already handles this by being invoked under sudo, and
# the sudoers entry covers `host/*/*` for our user. Future: bake
# pre-compiled DOF blobs as test fixtures so this can move to
# `cargo test` proper.
#
# Exit codes:
#   0 — every demo passes static-check
#   1 — at least one demo failed
#
# Usage:
#   scripts/check_lowering.sh
#   scripts/check_lowering.sh --quiet    # only print on failure
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
BIFROST="$REPO/host/runtime/bifrost"
DEMO_DIR="$REPO/host/runtime"

QUIET=0
[[ "${1:-}" == "--quiet" ]] && QUIET=1

if [[ ! -x "$BIFROST" ]]; then
    echo "error: $BIFROST not found or not executable" >&2
    echo "       run 'cargo build --release --manifest-path host/bifrost/Cargo.toml' first" >&2
    exit 1
fi

failed=0
total=0
out_dir="$(mktemp -d)"
trap "rm -rf '$out_dir'" EXIT

for d in "$DEMO_DIR"/bifrost_*.d "$DEMO_DIR"/bifrost.d; do
    [[ -f "$d" ]] || continue
    name=$(basename "$d" .d)
    # Skip non-bifrost demos (those without a bifrost: clause). The
    # runner refuses them with a clear error; that's expected, not
    # a lowering regression.
    if ! grep -qE '^bifrost:' "$d"; then
        [[ "$QUIET" -eq 0 ]] && echo "[skip] $name (no bifrost: clause)"
        continue
    fi
    total=$((total + 1))

    out=$(sudo "$BIFROST" --emit-ebpf "$out_dir/$name.ebpf" -s "$d" 2>&1) || true

    if echo "$out" | grep -qE 'verification failed'; then
        echo "[FAIL] $name"
        echo "$out" | grep -E 'verification failed' | head -1 | sed 's/^/       /'
        failed=$((failed + 1))
    elif echo "$out" | grep -qE 'wrote'; then
        n=$(echo "$out" | grep -cE '^\[bifrost\] prog #')
        [[ "$QUIET" -eq 0 ]] && echo "[ ok ] $name ($n progs)"
    else
        echo "[FAIL] $name (unexpected output)"
        echo "$out" | tail -3 | sed 's/^/       /'
        failed=$((failed + 1))
    fi
done

echo
if [[ $failed -eq 0 ]]; then
    echo "$total/$total demos passed static-check"
    exit 0
else
    echo "$failed/$total demos FAILED"
    exit 1
fi
