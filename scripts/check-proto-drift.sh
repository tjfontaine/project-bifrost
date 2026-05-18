#!/usr/bin/env bash
# check-proto-drift.sh — Detect drift in protocol constants that are
# defined in more than one source tree (host / libkrun / guest).
#
# The bifrost wire format has constants that, today, are independently
# defined in multiple crates because the guest is a kernel module
# (no Cargo.toml) and cannot consume a workspace crate.  This script
# is the cheap first line of defence: it greps for known constants in
# each layer and asserts the values match.
#
# Drift detected here means: someone changed a value in one layer but
# missed the matching definition elsewhere.  Run as a pre-commit hook
# alongside scripts/verify-patches.sh.
#
# Exit 0 = no drift, exit 1 = drift detected.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONDUIT_CRATE="$ROOT/host/virtio-conduit/src"
CONDUIT_LIB="$CONDUIT_CRATE/lib.rs"
GUEST_DRIVER="$ROOT/third_party/linux-bifrost/drivers/bifrost/bifrost.rs"
GUEST_SHMEM_LAYOUT="$ROOT/third_party/linux-bifrost/drivers/bifrost/shmem_layout.rs"
GUEST_WIRE="$ROOT/third_party/linux-bifrost/drivers/bifrost/wire.rs"
HOST_BIN="$ROOT/host/bifrost/src/bin/bifrost.rs"
HOST_WRAPPER="$ROOT/host/bifrost/src/cli/wrapper.rs"

fail=0

# extract_value FILE NAME — print a simple numeric literal for a
# `[const|pub const|pub(crate) const|pub(super) const] NAME: u8/u32/u64 = …`
# line.  Tolerant of any visibility modifier, leading whitespace, and
# trailing semicolon/comment.
extract_value() {
    local file=$1 name=$2
    grep -E "^[[:space:]]*(pub(\([^)]+\))? )?const ${name}:[[:space:]]*u(8|32|64)[[:space:]]*=" "$file" 2>/dev/null \
        | head -1 \
        | sed -E 's/^[[:space:]]*(pub(\([^)]+\))? )?const [A-Z_]+:[[:space:]]*u(8|32|64)[[:space:]]*=[[:space:]]*//' \
        | sed -E 's#[[:space:]]*//.*$##' \
        | sed -E 's/[[:space:]]*;.*$//' \
        | tr 'A-F' 'a-f'
}

# normalize_hex VAL — render a numeric literal (possibly 0xABCD or
# 4294967295) as a canonical decimal so the equality check is
# representation-agnostic.
normalize_hex() {
    local v=$1
    if [[ -z $v ]]; then echo ""; return; fi
    # strip underscores Rust allows in numeric literals
    v=${v//_/}
    v=${v//[[:space:]]/}
    if [[ $v == *'<<'* ]]; then echo "$v"
    elif [[ $v == 0x* ]]; then printf '%u\n' "$v"
    else echo "$v"; fi
}

# check_pair LAYER_A FILE_A NAME_A LAYER_B FILE_B NAME_B
# Compare two named constants; flag if either is missing or values differ.
check_pair() {
    local la=$1 fa=$2 na=$3 lb=$4 fb=$5 nb=$6
    local va vb va_n vb_n

    va=$(extract_value "$fa" "$na" || true)
    vb=$(extract_value "$fb" "$nb" || true)

    if [[ -z $va ]]; then
        echo "[drift] missing in $la: $na (looked in $fa)"
        fail=1
        return
    fi
    if [[ -z $vb ]]; then
        echo "[drift] missing in $lb: $nb (looked in $fb)"
        fail=1
        return
    fi

    va_n=$(normalize_hex "$va")
    vb_n=$(normalize_hex "$vb")

    if [[ $va_n != $vb_n ]]; then
        echo "[drift] $la::$na = $va  vs  $lb::$nb = $vb"
        fail=1
    fi
}

echo "[check-proto-drift] cross-layer constant audit"

# Wire-format consumers each handle the canonical file differently
# because their build environments differ:
#
#   libkrun: consumes the generic host/virtio-conduit crate through
#     a thin virtio adapter.  It no longer owns any Bifrost semantic
#     wire constants.
#
#   guest:   VENDORED COPY with a SHA256 pin in the header.  The
#     kernel build runs inside a krunvm with only libkrunfw/
#     mounted, so a symlink to host/bifrost-wire/ wouldn't
#     resolve at build time.  Vendoring + SHA pin gives the same
#     anti-drift guarantee with manual sync discipline.
HOST_WIRE_CRATE_FILE="$ROOT/host/bifrost-wire/src/lib.rs"
canon_sha=$(shasum -a 256 "$HOST_WIRE_CRATE_FILE" 2>/dev/null | awk '{print $1}')

# guest: SHA-pin check.  The vendored copy carries a header line
# `// CANONICAL_SHA256: <hex>` recording the canonical hash at
# vendor time; we recompute and compare.
if [[ -f $GUEST_WIRE ]]; then
    declared_sha=$(grep -oE 'CANONICAL_SHA256: [0-9a-f]{64}' "$GUEST_WIRE" 2>/dev/null \
        | head -1 \
        | awk '{print $2}')
    if [[ -z $declared_sha ]]; then
        echo "[drift] guest wire.rs missing CANONICAL_SHA256 pin: $GUEST_WIRE"
        echo "        fix: re-vendor from canonical and add the SHA-pin header"
        fail=1
    elif [[ "$declared_sha" != "$canon_sha" ]]; then
        echo "[drift] guest wire.rs CANONICAL_SHA256 doesn't match canonical:"
        echo "        declared (in vendored copy):  $declared_sha"
        echo "        actual (canonical sha256):    $canon_sha"
        echo "        fix: re-vendor from canonical and update the SHA pin"
        echo "             (the canonical file changed since the vendored copy was made)"
        fail=1
    fi
fi

# Per-constant value audits are still useful — they catch the
# case where someone changes the constants in canonical without
# bumping any caller, and surface the value in the lint output.
HOST_WIRE_CRATE="$HOST_WIRE_CRATE_FILE"

# Probe-ID constants — host/guest audit. libkrun intentionally does
# not define these semantic record ids.
check_pair \
    bifrost-wire "$HOST_WIRE_CRATE" AGG_SNAPSHOT_PROBE_ID \
    guest        "$GUEST_WIRE"     AGG_SNAPSHOT_PROBE_ID

check_pair \
    bifrost-wire "$HOST_WIRE_CRATE" SYM_TABLE_PROBE_ID \
    guest        "$GUEST_WIRE"     SYM_TABLE_PROBE_ID

check_pair \
    bifrost-wire "$HOST_WIRE_CRATE" VMA_TABLE_PROBE_ID \
    guest        "$GUEST_WIRE"     VMA_TABLE_PROBE_ID

# Virtio conduit data-plane invariants.  The guest decides the Bifrost
# SHMEM sub-layout, but the VMM-owned virtio shared-memory region must
# be at least the same size and currently is exactly the same size.
conduit_region_expr=$(grep -E '^[[:space:]]*pub const VIRTIO_SHM_REGION_SIZE:[[:space:]]*usize[[:space:]]*=' "$CONDUIT_LIB" 2>/dev/null \
    | head -1 \
    | sed -E 's/^[^=]+=[[:space:]]*//' \
    | sed -E 's/[[:space:]]*;.*$//')
guest_region_expr=$(grep -E '^[[:space:]]*pub(\([^)]+\))?[[:space:]]+const SHMEM_REGION_SIZE:[[:space:]]*usize[[:space:]]*=' "$GUEST_SHMEM_LAYOUT" 2>/dev/null \
    | head -1 \
    | sed -E 's/^[^=]+=[[:space:]]*//' \
    | sed -E 's/[[:space:]]*;.*$//')

if [[ -z $conduit_region_expr ]]; then
    echo "[drift] missing in virtio-conduit: VIRTIO_SHM_REGION_SIZE (looked in $CONDUIT_LIB)"
    fail=1
elif [[ -z $guest_region_expr ]]; then
    echo "[drift] missing in guest: SHMEM_REGION_SIZE (looked in $GUEST_SHMEM_LAYOUT)"
    fail=1
elif [[ ${conduit_region_expr//[[:space:]]/} != "${guest_region_expr//[[:space:]]/}" ]]; then
    echo "[drift] virtio-conduit::VIRTIO_SHM_REGION_SIZE = $conduit_region_expr  vs  guest::SHMEM_REGION_SIZE = $guest_region_expr"
    fail=1
fi

check_pair \
    bifrost-wire "$HOST_WIRE_CRATE" SHMEM_MAGIC \
    guest        "$GUEST_SHMEM_LAYOUT" SHMEM_MAGIC
check_pair \
    bifrost-wire "$HOST_WIRE_CRATE" SHMEM_VERSION \
    guest        "$GUEST_SHMEM_LAYOUT" SHMEM_VERSION

# The generic conduit must stay Bifrost-agnostic. BFR7, semantic
# probe ids, D4 observer handshakes, SHMEM records, stacks, VMAs,
# symbols, profile samples, and aggregations belong in host/bifrost
# plus the guest kernel copy only.
if grep -REq '^[[:space:]]*pub const (BFR7|VMA_TABLE|SYM_TABLE|AGG_|SHMEM_RECORD|PROFILE_SAMPLE|D4_KIND_|FEATURE_|HELLO_REJECT_|LOAD_PROG_BATCH)' "$CONDUIT_CRATE" 2>/dev/null; then
    echo "[drift] virtio-conduit exposes Bifrost tracing semantic constants"
    fail=1
fi

if [[ $fail -eq 0 ]]; then
    echo "[check-proto-drift] OK: all cross-layer constants match"
fi

exit $fail
