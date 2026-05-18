#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# verify-patches.sh — fail if libkrunfw/patches/ has drifted from
# the linux-bifrost source-of-truth branch.
#
# Why: the canonical workflow (codified in AGENTS.md) treats
# linux-bifrost as the source-of-truth for kernel patches; the
# libkrunfw/patches/ tree is GENERATED via `git format-patch` and
# must never be hand-edited. This lint catches the next round of
# drift before it blocks: hand-edited patches, missing commits,
# orphan patches, hunk count mismatches.
#
# Run:
#   sh scripts/verify-patches.sh
#
# Exit status:
#   0 — all bifrost-branch commits have a matching patch with
#       identical hunk content
#   1 — drift detected (printed); fix by re-running format-patch
#       against linux-bifrost or by adjusting the linux-bifrost
#       branch
#
# The current bifrost/v6.12.76 branch carries `NNNN-` prefixes in
# commit subjects (e.g. "0028-bifrost-rust-bindings-..."), which
# makes `git format-patch` produce DOUBLE-prefixed filenames
# (`0028-0028-bifrost-rust-bindings-…patch`). Reconciliation then
# hand-renames the files. This script tolerates the rename by
# matching on canonicalized SUBJECT, not filename. Once the
# subject-line cleanup lands, the
# canonicalization here can be simplified.
#
# Two accepted exceptions in libkrunfw/patches/:
#   - 0023-UPSTREAM-NOTES.md (documentation, not a patch)
#   - 0023-overlayfs-Handle-EOPNOTSUPP-in-fileattr-copy-up.patch
#     (libkrunfw-only; not present in linux-bifrost)

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LINUX_BIFROST="$ROOT/third_party/linux-bifrost"
PATCHES_DIR="$ROOT/third_party/smolvm/libkrunfw/patches"
TMP="$(mktemp -d -t verify-patches.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

# Locate the base ref. The branch is `bifrost/v6.12.76`; the base
# is the upstream "Linux 6.12.76" commit, identified by its
# canonical subject.
BASE=$(git -C "$LINUX_BIFROST" log --grep='^Linux 6\.12\.76$' --format=%H -1)
if [ -z "$BASE" ]; then
    echo "[verify-patches] could not find 'Linux 6.12.76' base commit" >&2
    exit 1
fi

git -C "$LINUX_BIFROST" format-patch \
    "$BASE..bifrost/v6.12.76" -o "$TMP/generated/" >/dev/null

# Canonicalize a patch's subject so generated and existing patches
# match even when wrapped differently or carrying drift-prone
# prefixes.
#
# The Subject line in a `git format-patch`-generated mbox looks like:
#   Subject: [PATCH NN/MM] 0028-bifrost-rust-bindings: rust bindings…
# The leading `[PATCH NN/MM]` is added by format-patch, the leading
# `NNNN-some-slug:` is the legacy commit-subject prefix carried on
# the bifrost branch, and the actual subject is what follows the colon.
#
# Existing libkrunfw/patches/ files carry just the actual subject:
#   Subject: [PATCH] krunfw: Don't panic when init dies
#
# Steps:
#   1. join multi-line Subject (long subjects wrap with continuation
#      lines starting with whitespace).
#   2. strip the `Subject: ` label.
#   3. strip the `[PATCH...]` annotation (any contents inside).
#   4. strip a leading `NNNN-...: ` legacy prefix (≥1 digit run +
#      one or more `-word` segments + `: `). Only one such prefix
#      may exist; we don't strip recursively to avoid eating real
#      colons in the actual subject.
#   5. collapse whitespace.
canonical_subject() {
    awk '
        /^Subject:/ { in_s = 1; print; next }
        /^[[:space:]]/ && in_s { sub(/^[[:space:]]*/, " "); print; next }
        in_s { exit }
    ' "$1" \
        | tr -d '\n' \
        | sed -E '
            s/^Subject:[[:space:]]*//
            s/\[PATCH[^]]*\][[:space:]]*//
            s/^[0-9]+(-[A-Za-z0-9_]+)+:[[:space:]]*//
        ' \
        | tr -s '[:space:]' ' ' \
        | sed 's/^ //;s/ $//' \
        | sed -E '
            s/\?=[[:space:]]+=\?UTF-8\?[Qq]\?//g
            s/^=\?UTF-8\?[Qq]\?//
            s/\?=$//
        '
}

# Extract the diff section: everything from the first `diff --git`
# to the end-of-mbox `-- ` line (exclusive). Hunk content only —
# strips author/date/sha trailer that legitimately differs across
# regenerations of the same commit.
diff_body() {
    awk '
        /^diff --git/ { p = 1 }
        /^-- $/ { exit }
        p { print }
    ' "$1"
}

# Build subject → filepath maps for both sides.
declare_map() {
    name="$1"
    dir="$2"
    out="$TMP/${name}.map"
    : > "$out"
    for f in "$dir"/*.patch; do
        [ -f "$f" ] || continue
        # Skip non-patch files (UPSTREAM-NOTES.md happens to live in
        # patches/ but lacks a Subject line so canonical_subject
        # returns empty; treat that as "skip").
        sub=$(canonical_subject "$f")
        [ -n "$sub" ] || continue
        printf '%s\t%s\n' "$sub" "$f" >> "$out"
    done
}

declare_map generated "$TMP/generated"
declare_map existing "$PATCHES_DIR"

# Accepted exceptions (extra patches in libkrunfw/patches/ that
# don't have a corresponding linux-bifrost commit). Each entry is
# a CANONICALIZED subject line — the value canonical_subject()
# returns for that patch's mbox header.
ALLOW_ORPHAN_SUBJECTS='ovl: translate EOPNOTSUPP to ENOTTY in ovl_real_fileattr_get'

drift=0

# Check every linux-bifrost commit has a matching patch with
# identical hunk content.
while IFS=$(printf '\t') read -r sub gen_path; do
    [ -n "$sub" ] || continue
    existing_path=$(awk -F'\t' -v s="$sub" '$1 == s { print $2; exit }' "$TMP/existing.map")
    if [ -z "$existing_path" ]; then
        echo "[verify-patches] DRIFT: missing patch for commit:"
        echo "                 $sub"
        echo "                 expected in $PATCHES_DIR"
        drift=1
        continue
    fi
    diff_body "$gen_path"      > "$TMP/gen.diff"
    diff_body "$existing_path" > "$TMP/exi.diff"
    if ! diff -q "$TMP/gen.diff" "$TMP/exi.diff" >/dev/null 2>&1; then
        echo "[verify-patches] DRIFT: hunk content differs for:"
        echo "                 $sub"
        echo "                 existing: $(basename "$existing_path")"
        echo "                 generated: $(basename "$gen_path")"
        echo "                 (run 'diff <(<format-patch>) $existing_path' for details)"
        drift=1
    fi
done < "$TMP/generated.map"

# Check no orphan existing patches (every libkrunfw patch should
# either match a linux-bifrost commit or be on the allow-list).
while IFS=$(printf '\t') read -r sub existing_path; do
    [ -n "$sub" ] || continue
    if awk -F'\t' -v s="$sub" '$1 == s { found = 1; exit } END { exit !found }' "$TMP/generated.map"; then
        continue  # matched
    fi
    case "
$ALLOW_ORPHAN_SUBJECTS
" in
        *"
$sub
"*) continue ;;
    esac
    echo "[verify-patches] DRIFT: orphan patch (no matching linux-bifrost commit):"
    echo "                 $sub"
    echo "                 file: $(basename "$existing_path")"
    drift=1
done < "$TMP/existing.map"

if [ "$drift" -ne 0 ]; then
    echo "[verify-patches] FAIL: drift detected (see above)"
    exit 1
fi

echo "[verify-patches] OK: $(wc -l < "$TMP/generated.map" | tr -d ' ') commits match patches in $PATCHES_DIR"
