#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# check-kfunc-manifest.sh — fail the build if the bifrost C-side
# kfunc manifest in bifrost_helpers.c disagrees with the Rust-side
# expected manifest in kfunc_manifest.rs.
#
# Why: the Rust ↔ C boundary for the bifrost_helper_* surface is an
# implicit ABI today.  A silent signature change on one side would
# either compile cleanly with hidden UB at runtime, or surface as a
# kernel oops on first call.  This manifest check closes the loop:
#
#   1. bifrost_helpers.c carries the canonical manifest in a static
#      const array `BIFROST_KFUNC_MANIFEST` of (name, signature_string)
#      entries.
#   2. kfunc_manifest.rs carries the same list in BIFROST_KFUNC_EXPECTED.
#   3. bifrost_kfunc_manifest_hash() returns a djb2 hash of the
#      concatenated (name, sig) pairs.  Module init compares against
#      the const-evaluated Rust hash; mismatch ⇒ refuse module load.
#   4. *This script* runs before module load even comes into play.
#      It parses both manifests, prints a diff if they disagree, and
#      exits non-zero so a precommit hook / CI gate refuses to ship
#      the broken pair.
#
# Run:
#   sh scripts/check-kfunc-manifest.sh
#
# Exit status:
#   0 — both manifests list the same (name, sig) entries in the same
#       order
#   1 — drift detected (printed); fix by editing both files until
#       they agree
#
# Limitations:
#   - The parser is text-based.  Reformatting either array (adding
#     blank lines, changing brace style) may upset it.  When that
#     happens, fix the parser; don't disable the lint.

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
C_FILE="$ROOT/third_party/linux-bifrost/drivers/bifrost/bifrost_helpers.c"
RUST_FILE="$ROOT/third_party/linux-bifrost/drivers/bifrost/kfunc_manifest.rs"
TMP="$(mktemp -d -t kfunc-manifest.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

# Extract C manifest entries.  The block looks like:
#
#   static const struct bifrost_kfunc_decl BIFROST_KFUNC_MANIFEST[] = {
#       {
#           "bifrost_helper_find_task_by_comm",
#           "struct task_struct *(const unsigned char *, unsigned int)",
#       },
#       ...
#   };
#
# Slice out the body with sed (between the array opener and the
# closing `};`), then grep one quoted string per line, then pair them
# up two at a time into name<TAB>sig.  Pure POSIX — works on macOS
# awk and GNU awk alike.
sed -n '/BIFROST_KFUNC_MANIFEST\[\] *= *{/,/^};/p' "$C_FILE" \
    | grep -oE '"[^"]+"' \
    | sed 's/^"//; s/"$//' \
    | awk 'NR%2==1 { name=$0; next } { printf "%s\t%s\n", name, $0 }' \
    > "$TMP/c.tsv"

# Extract Rust manifest entries.  The block looks like:
#
#   const BIFROST_KFUNC_EXPECTED: &[KfuncDecl] = &[
#       KfuncDecl {
#           name: b"bifrost_helper_find_task_by_comm",
#           sig: b"struct task_struct *(const unsigned char *, unsigned int)",
#       },
#       ...
#   ];
#
# Same approach — pull `b"..."` byte-string literals two at a time.
sed -n '/BIFROST_KFUNC_EXPECTED.*= *&\[/,/^];/p' "$RUST_FILE" \
    | grep -oE 'b"[^"]+"' \
    | sed 's/^b"//; s/"$//' \
    | awk 'NR%2==1 { name=$0; next } { printf "%s\t%s\n", name, $0 }' \
    > "$TMP/rust.tsv"

# Both files extracted.  Compare.
if [ ! -s "$TMP/c.tsv" ]; then
    echo "[check-kfunc-manifest] ERROR: parsed zero entries from $C_FILE" >&2
    echo "                       (block markers BIFROST_KFUNC_MANIFEST[] and };)" >&2
    exit 1
fi
if [ ! -s "$TMP/rust.tsv" ]; then
    echo "[check-kfunc-manifest] ERROR: parsed zero entries from $RUST_FILE" >&2
    echo "                       (block markers BIFROST_KFUNC_EXPECTED and ];)" >&2
    exit 1
fi

if diff -u "$TMP/c.tsv" "$TMP/rust.tsv" > "$TMP/diff" 2>&1; then
    c_count=$(wc -l < "$TMP/c.tsv" | awk '{print $1}')
    echo "[check-kfunc-manifest] OK: $c_count kfunc entries match across bifrost_helpers.c and kfunc_manifest.rs"
    exit 0
fi

echo "[check-kfunc-manifest] DRIFT: bifrost_helpers.c manifest disagrees with kfunc_manifest.rs expected manifest" >&2
echo "                       diff (- = C side, + = Rust side):" >&2
sed 's/^/                       /' "$TMP/diff" >&2
echo >&2
echo "[check-kfunc-manifest] fix: edit both files so each (name, signature) pair matches in order" >&2
exit 1
