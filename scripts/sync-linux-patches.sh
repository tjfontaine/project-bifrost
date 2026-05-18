#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# sync-linux-patches.sh — verify that the patch series carried in
# `third_party/linux-bifrost` (as commits) is in sync with
# `third_party/smolvm/libkrunfw/patches/` (as .patch files).
#
# The build flow on a fresh clone is: smolvm/libkrunfw downloads
# vanilla linux-6.12.76 from cdn.kernel.org and applies its own
# `patches/` directory, in numbered order, to produce vmlinux. The
# `linux-bifrost` submodule is a "patches as commits" view of the
# same series — useful for browsing, bisecting, and authoring new
# patches. The two should be 1:1.
#
# Matching is by *slug* (normalised subject / filename body): a
# commit `bifrost: add guest tracing support` matches the patch
# `0028-bifrost-add-guest-tracing-support.patch` even when the
# commit subject doesn't carry the `NNNN-` prefix.  Number
# mismatches under the same slug are reported as a separate
# "renumber-needed" class.
#
# Usage:
#   scripts/sync-linux-patches.sh           # check only
#   scripts/sync-linux-patches.sh --export  # also write missing
#                                           # patches via git
#                                           # format-patch (preview;
#                                           # does not commit)
#
# Bash-3.2-safe (no associative arrays) — runs under macOS's stock
# /bin/bash without brew.

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LINUX_DIR="$ROOT/third_party/linux-bifrost"
PATCHES_DIR="$ROOT/third_party/smolvm/libkrunfw/patches"
EXPORT_DIR="${EXPORT_DIR:-$ROOT/.sync-linux-patches.out}"

if [ ! -d "$LINUX_DIR/.git" ] && [ ! -f "$LINUX_DIR/.git" ]; then
    echo "error: $LINUX_DIR is not a git submodule (run git submodule update --init)"
    exit 1
fi
if [ ! -d "$PATCHES_DIR" ]; then
    echo "error: $PATCHES_DIR not found (smolvm submodule missing?)"
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# normalize_slug RAW — lowercase, replace whitespace/punct with
# dashes, drop a leading NNNN- if any, drop a trailing `-patch`,
# drop terminal noise after the first colon.  Same shape that
# libkrunfw uses when running `git format-patch | xargs git
# am`.
normalize_slug() {
    printf '%s' "$1" \
        | tr 'A-Z' 'a-z' \
        | sed -E 's/^[0-9]{4}-//' \
        | sed -E 's/[^a-z0-9]+/-/g' \
        | sed -E 's/^-+|-+$//g' \
        | cut -c1-48
}

# 1. Numbered + slugged commits in linux-bifrost.
#    Format: NNNN<TAB>SHA<TAB>SUBJECT-after-NNNN<TAB>SLUG
#    NNNN comes from a `NNNN-` subject prefix if present, else
#    falls back to 0000 (resolved by slug-match against patches).
(
    cd "$LINUX_DIR"
    # Bifrost-tracked commits are a non-trivial subset of the
    # ~1.3M-commit Linux history.  Restrict to subjects whose
    # first word/path is one of the four prefixes we use:
    #   NNNN-<slug>:   numbered patch-as-commit (older convention)
    #   bifrost:       bare bifrost commit (current convention)
    #   krunfw:        libkrunfw-side patch (e.g. 0001/0002)
    # Plus a handful of vendor-imported reverts/feature commits
    # whose subjects start with the literal "Revert" / "virtio" /
    # "vsock" / "tsi" / "fuse" / "dax" / "drm" / "arm64" /
    # "prctl" / "mm" / "can" / "Linux" — those we match on the
    # numeric prefix only.
    git log --format='%H	%s' \
        | LC_ALL=C awk -F'\t' '
            $2 ~ /^0[0-2][0-9]{2}-/ {
                num = substr($2, 1, 4)
                rest = substr($2, 6)
                gsub(/:.*$/, "", rest)
                print num "\t" $1 "\t" rest
                next
            }
            $2 ~ /^bifrost:/ {
                rest = $2
                sub(/^bifrost: */, "bifrost-", rest)
                gsub(/[^A-Za-z0-9-]/, "-", rest)
                gsub(/-+/, "-", rest)
                sub(/-$/, "", rest)
                print "0000\t" $1 "\t" rest
            }
        ' \
        > "$WORK/commits_raw"
    # For each commit, derive a slug via normalize_slug.
    while IFS=$'\t' read -r num sha rest; do
        slug=$(printf '%s' "$rest" | tr 'A-Z' 'a-z' \
                                   | sed -E 's/^[0-9]{4}-//' \
                                   | sed -E 's/[^a-z0-9]+/-/g' \
                                   | sed -E 's/^-+|-+$//g' \
                                   | cut -c1-30 \
                                   | sed -E 's/-+$//')
        printf '%s\t%s\t%s\t%s\n' "$num" "$sha" "$rest" "$slug"
    done < "$WORK/commits_raw" | sort -k4,4 > "$WORK/commits"
)

# 2. Numbered patch files.
#    Format: NNNN<TAB>FILENAME-after-NNNN<TAB>FULL-PATH<TAB>SLUG
(
    for f in "$PATCHES_DIR"/*.patch; do
        [ -e "$f" ] || continue
        base="$(basename "$f" .patch)"
        case "$base" in
            [0-9][0-9][0-9][0-9]-*)
                num="${base%%-*}"
                rest="${base#*-}"
                slug=$(printf '%s' "$rest" | tr 'A-Z' 'a-z' \
                                          | sed -E 's/[^a-z0-9]+/-/g' \
                                          | sed -E 's/^-+|-+$//g' \
                                          | cut -c1-30 \
                                   | sed -E 's/-+$//')
                printf '%s\t%s\t%s\t%s\n' "$num" "$rest" "$f" "$slug"
                ;;
        esac
    done | sort -k4,4
) > "$WORK/patches"

cut -f4 "$WORK/commits" | sort -u > "$WORK/commit_slugs"
cut -f4 "$WORK/patches" | sort -u > "$WORK/patch_slugs"

# libkrunfw filenames sometimes duplicate the subject body (the
# `git format-patch` template + libkrunfw's renaming both prefix
# the body, yielding "NNNN-<body>-<body-prefix>.patch").  Match
# by *prefix*: a commit's slug matches a patch's slug iff one is
# a prefix of the other.
match_slug() {
    local commit_slug=$1 patch_slug=$2
    case "$patch_slug" in
        "$commit_slug"*) return 0 ;;
    esac
    case "$commit_slug" in
        "$patch_slug"*) return 0 ;;
    esac
    return 1
}

# Build matched-pair list by iterating commits, looking for a
# matching patch slug.
> "$WORK/matched_commits"
> "$WORK/matched_patches"
while IFS= read -r cs; do
    [ -n "$cs" ] || continue
    while IFS= read -r ps; do
        [ -n "$ps" ] || continue
        if match_slug "$cs" "$ps"; then
            printf '%s\t%s\n' "$cs" "$ps" >> "$WORK/matched_commits"
            printf '%s\t%s\n' "$cs" "$ps" >> "$WORK/matched_patches"
            break
        fi
    done < "$WORK/patch_slugs"
done < "$WORK/commit_slugs"
cut -f1 "$WORK/matched_commits" | sort -u > "$WORK/cs_matched"
cut -f2 "$WORK/matched_patches" | sort -u > "$WORK/ps_matched"

COMMIT_ONLY=$(comm -23 "$WORK/commit_slugs" "$WORK/cs_matched")
PATCH_ONLY=$(comm -23 "$WORK/patch_slugs" "$WORK/ps_matched")
SHARED=$(cat "$WORK/cs_matched")

# Accepted libkrunfw-only patches (mirrors the ALLOW_ORPHAN_SUBJECTS
# list in verify-patches.sh).  These are patches libkrunfw carries
# directly without a matching linux-bifrost commit, typically
# because they're applied to a path the bifrost branch doesn't
# touch.  Slugs match the libkrunfw-renamed filename prefix.
ALLOW_PATCH_ONLY='overlayfs-handle-eopnotsupp-in'
if [ -n "$PATCH_ONLY" ]; then
    filtered=""
    while IFS= read -r slug; do
        [ -n "$slug" ] || continue
        keep=1
        for allowed in $ALLOW_PATCH_ONLY; do
            if [ "$slug" = "$allowed" ]; then
                keep=0
                break
            fi
        done
        if [ "$keep" -eq 1 ]; then
            filtered="${filtered}${slug}
"
        fi
    done <<EOF_PATCH_ONLY
$PATCH_ONLY
EOF_PATCH_ONLY
    PATCH_ONLY="${filtered%$'\n'}"
fi

echo "=== linux-bifrost commits with no matching libkrunfw/patches/ entry ==="
if [ -z "$COMMIT_ONLY" ]; then
    echo "  (none)"
else
    while IFS= read -r slug; do
        [ -n "$slug" ] || continue
        line=$(grep -F "	$slug" "$WORK/commits" | head -1)
        num=$(echo "$line" | cut -f1)
        sha=$(echo "$line" | cut -f2)
        rest=$(echo "$line" | cut -f3)
        echo "  $num  $sha  $rest  ($slug)"
    done <<EOF_LIST
$COMMIT_ONLY
EOF_LIST
fi

echo
echo "=== libkrunfw/patches/ files with no matching linux-bifrost commit ==="
if [ -z "$PATCH_ONLY" ]; then
    echo "  (none)"
else
    while IFS= read -r slug; do
        [ -n "$slug" ] || continue
        line=$(grep -F "	$slug" "$WORK/patches" | head -1)
        num=$(echo "$line" | cut -f1)
        rest=$(echo "$line" | cut -f2)
        echo "  $num  $rest  ($slug)"
    done <<EOF_LIST
$PATCH_ONLY
EOF_LIST
fi

echo
echo "=== Number-renumber-needed (same slug, different prefix) ==="
renumbers=0
for slug in $SHARED; do
    commit_num=$(grep -F "	$slug" "$WORK/commits" | head -1 | cut -f1)
    patch_num=$(grep -F "	$slug" "$WORK/patches" | head -1 | cut -f1)
    if [ "$commit_num" != "0000" ] && [ "$commit_num" != "$patch_num" ]; then
        echo "  commit $commit_num vs patch $patch_num  ($slug)"
        renumbers=$((renumbers + 1))
    fi
done
[ "$renumbers" -eq 0 ] && echo "  (none)"

echo
co_count=$(echo "$COMMIT_ONLY" | grep -c . || true)
po_count=$(echo "$PATCH_ONLY" | grep -c . || true)
total=$(( co_count + po_count + renumbers ))
if [ "$total" -eq 0 ]; then
    echo "✓ linux-bifrost and libkrunfw/patches/ are in sync."
    exit 0
fi
echo "drift summary: $co_count commit-only, $po_count patch-only, $renumbers renumber(s)"

# Optional export step.
if [ "${1:-}" = "--export" ]; then
    echo
    echo "=== --export: writing patch files for commit-only entries ==="
    mkdir -p "$EXPORT_DIR"
    cd "$LINUX_DIR"
    while IFS= read -r slug; do
        [ -n "$slug" ] || continue
        line=$(grep -F "	$slug" "$WORK/commits" | head -1)
        num=$(echo "$line" | cut -f1)
        sha=$(echo "$line" | cut -f2)
        # If commit has no NNNN prefix, find the next free patch
        # number after the highest existing one.
        if [ "$num" = "0000" ]; then
            num=$(cut -f1 "$WORK/patches" | sort -n | tail -1)
            num=$(printf '%04d' "$(( 10#$num + 1 ))")
        fi
        out=$(git format-patch -1 --start-number "$(printf '%d' "$num")" \
                                  --output-directory "$EXPORT_DIR" \
                                  "$sha" 2>&1 | tail -1)
        echo "  wrote: $out"
    done <<EOF_LIST
$COMMIT_ONLY
EOF_LIST
    echo
    echo "Patches exported to $EXPORT_DIR/. Review then copy into"
    echo "$PATCHES_DIR/ and commit on the smolvm/libkrunfw submodule."
fi

exit 1
