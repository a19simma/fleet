#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 DIST_ARCHIVE_DIR OUT_DIR" >&2
  exit 2
fi
src=$1
out=$2

here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"
for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  python3 "$here/repack_archive.py" \
    --from "$src/fleetd-$target.tar.gz" \
    --out "$out/fleetd-$target.tar.gz"
done
