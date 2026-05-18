#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# check-no-active-bfr7.sh — gate against the host CLI actively
# producing BFR7 / LOAD_PROG_BATCH payloads.
#
# Spec: after the DOF-generic rebuild, the host CLI emits one
# `DTRACE_SESSION_V1` envelope per session and never lowers D to eBPF
# itself.  Lowering becomes the Linux driver's job via
# `crates/bifrost-dtrace-lower`; libkrun ferries the session envelope
# opaquely.
#
# This script keeps that contract enforceable.  It walks
# `host/bifrost/src/` for call sites of the BFR7 wrapper emitters and
# classifies each as:
#
#   - producer    — a live call site that builds a BFR7 wrapper for
#                   transmission to the guest.
#   - decoder     — a call site that only inspects the magic to parse
#                   legacy bytes (e.g. self-test recordings).  Allowed.
#   - fixture     — `#[cfg(test)]` / tests/ / examples/ fixtures.
#                   Allowed.
#
# Modes:
#   default   — print classification, exit 0.  Useful for tracking
#               cutover progress in CI without flipping the gate.
#   --strict  — exit non-zero if any `producer` row is found.  Flip
#               this once the host has migrated all live LOAD_PROG
#               emission to DTRACE_SESSION_V1.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_BIFROST="$ROOT/host/bifrost/src"

mode="warn"
if [[ "${1:-}" == "--strict" ]]; then
    mode="strict"
fi

producers=()
decoders=()
fixtures=()

scan() {
    local file="$1"
    local lineno content classify
    while IFS=: read -r lineno content; do
        [[ -z "$lineno" ]] && continue
        # Skip doc comments and historical references.
        if [[ "$content" == *"//"* && "$content" == *"build_wrapper_bytes"* ]]; then
            local code="${content%%//*}"
            if [[ "$code" != *"build_wrapper_bytes"* && "$code" != *"BFR7_MAGIC"* && "$code" != *"LOAD_PROG_BATCH_MAGIC"* ]]; then
                continue
            fi
        fi

        classify="producer"
        # tests/ and examples/ files: fixture.
        if [[ "$file" == */tests/* || "$file" == */examples/* ]]; then
            classify="fixture"
        fi
        # Lines inside the wrapper.rs definition itself are not call
        # sites, just the definition; classify as decoder so we don't
        # report build_wrapper_bytes against its own decl.
        if [[ "$file" == */cli/wrapper.rs ]]; then
            classify="decoder"
        fi
        # Decode-only readers of BFR7_MAGIC (parsing legacy bytes).
        if [[ "$content" == *"== BFR7_MAGIC"* || "$content" == *"!= BFR7_MAGIC"* ]]; then
            classify="decoder"
        fi
        # `#[cfg(test)]`-adjacent: cheap heuristic — file path under
        # cli/source_rewrite_tests.rs or any *_tests.rs.
        if [[ "$file" == *_tests.rs ]]; then
            classify="fixture"
        fi
        case "$classify" in
            producer) producers+=("${file#$ROOT/}:$lineno: $content") ;;
            decoder)  decoders+=("${file#$ROOT/}:$lineno: $content") ;;
            fixture)  fixtures+=("${file#$ROOT/}:$lineno: $content") ;;
        esac
    done < <(grep -nE 'build_wrapper_bytes|LOAD_PROG_BATCH_MAGIC|BFR7_MAGIC_LE' "$file" 2>/dev/null || true)
}

# Walk the host CLI sources.
while IFS= read -r file; do
    scan "$file"
done < <(find "$HOST_BIFROST" -name '*.rs' -type f)

echo "[check-no-active-bfr7] producers : ${#producers[@]}"
echo "[check-no-active-bfr7] decoders  : ${#decoders[@]}"
echo "[check-no-active-bfr7] fixtures  : ${#fixtures[@]}"

if [[ ${#producers[@]} -gt 0 ]]; then
    echo "" >&2
    echo "Active BFR7 producers (need to migrate to DTRACE_SESSION_V1):" >&2
    for row in "${producers[@]}"; do
        echo "  $row" >&2
    done
fi

if [[ "$mode" == "strict" && ${#producers[@]} -gt 0 ]]; then
    echo "" >&2
    echo "[check-no-active-bfr7] STRICT: refuse — host CLI still actively produces BFR7 wrappers." >&2
    echo "The host must emit DTRACE_SESSION_V1 only; the guest lowers DOF locally." >&2
    exit 1
fi

exit 0
