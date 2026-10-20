#!/usr/bin/env bash
# codeql-retrace-vendored.sh — the vendored C/C++ files a pull request changes,
# for the PR c-cpp CodeQL scan (.github/workflows/codeql.yml).
#
# A PR's c-cpp scan compiles the third-party objects BEFORE CodeQL starts
# tracing (scripts/build.sh --vendored-only), so vendored C stays out of the
# analysis, while ALL first-party C is traced -- except the vendored files the
# PR itself changes. This lists those; scripts/build.sh --reuse-vendored
# --retrace-from <list> then rebuilds their objects under tracing (make -W, so
# make's own dependency graph picks the objects).
#
# The changed files come from the PR merge commit (HEAD^1 is the base it was
# merged onto, as in pr.yml's file-list fallback; needs fetch-depth 2) unless
# --changed FILE gives them. An undeterminable diff (no pull request, no
# parent, git failing, an unreadable FILE) is NOT an error and never narrows
# the scan: the list is empty and the scan still covers all first-party C.
#
# Usage: scripts/ci/codeql-retrace-vendored.sh [--changed FILE] OUT
#   OUT is written with the vendored paths to retrace, one per line (may be
#   empty). The scope test is scripts/ci/select-lanes.sh --codeql-scope c-cpp.
# Exit: 0 = list written · 2 = usage error.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHANGED_FILE=""
OUT=""
while [ $# -gt 0 ]; do
    case "$1" in
    -h | --help)
        sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    --changed)
        CHANGED_FILE="${2:-}"
        [ -n "$CHANGED_FILE" ] || {
            echo "codeql-retrace-vendored.sh: --changed needs a file. Please consult --help." >&2
            exit 2
        }
        shift
        ;;
    -*)
        echo "codeql-retrace-vendored.sh: unknown option '$1'. Please consult --help." >&2
        exit 2
        ;;
    *)
        if [ -n "$OUT" ]; then
            echo "codeql-retrace-vendored.sh: more than one output file. Please consult --help." >&2
            exit 2
        fi
        OUT="$1"
        ;;
    esac
    shift
done
if [ -z "$OUT" ]; then
    echo "codeql-retrace-vendored.sh: no output file. Please consult --help." >&2
    exit 2
fi

changed=""
determined=false
if [ -n "$CHANGED_FILE" ]; then
    if [ -r "$CHANGED_FILE" ]; then
        changed=$(cat "$CHANGED_FILE")
        determined=true
    fi
elif [ "${GITHUB_EVENT_NAME:-}" = pull_request ]; then
    if changed=$(git -C "$ROOT" diff --name-only --no-renames HEAD^1 HEAD 2>/dev/null); then
        determined=true
    fi
fi

: >"$OUT"
if ! $determined; then
    echo "diff undetermined: no vendored file to retrace; the scan covers all first-party C"
    exit 0
fi
printf '%s\n' "$changed" |
    bash "$ROOT/scripts/ci/select-lanes.sh" --codeql-scope c-cpp |
    while IFS= read -r path; do
        case "$path" in
        internal/cbm/vendored/* | vendored/*)
            if [ -f "$ROOT/$path" ]; then printf '%s\n' "$path"; fi
            ;;
        esac
    done >"$OUT"
count=$(wc -l <"$OUT" | tr -d ' ')
echo "vendored files to retrace: $count"
cat "$OUT"
