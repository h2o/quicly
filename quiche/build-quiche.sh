#!/bin/sh
# Builds hq_server in a checkout of https://github.com/google/quiche given as $1, as $1/bazel-bin/ccbench/hq_server, which
# run-one.py --quiche runs.
#
# - quiche.patch is applied to the checkout if its tracked files are unmodified; otherwise their changes must be exactly
#   quiche.patch
# - this directory is linked into the checkout as ccbench/
# - --check_visibility=false: QUICHE's libraries are visible only within its own package; this avoids editing its BUILD
# - system_icu=0: googleurl's bundled IDNA instead of the system ICU (as QUICHE's .bazelrc does on macOS)
set -e
quiche="$1"
[ -n "$quiche" ] || { echo "usage: $0 QUICHE_CHECKOUT" >&2; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
if git -C "$quiche" diff --quiet HEAD; then
    git -C "$quiche" apply "$here/quiche.patch"
fi
git -C "$quiche" diff HEAD | cmp -s - "$here/quiche.patch" || { echo "$quiche has changes other than quiche.patch" >&2; exit 1; }
if [ ! -e "$quiche/ccbench" ]; then
    ln -s "$here" "$quiche/ccbench"
fi
[ "$(readlink -f "$quiche/ccbench")" = "$here" ] || { echo "$quiche/ccbench is not a link to $here" >&2; exit 1; }
cd "$quiche"
CC=clang CXX=clang++ bazelisk build -c opt --check_visibility=false \
    --@com_google_googleurl//build_config:system_icu=0 //ccbench:hq_server
