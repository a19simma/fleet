#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 5 ]; then
  echo "usage: $0 ARCHIVE_DIR TAG SEQ REPOSITORY OUT" >&2
  exit 2
fi
dir=$1
tag=$2
seq=$3
repo=$4
out=$5

version=$(printf '%s' "$tag" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+.*$' || true)
if [ -z "$version" ]; then
  echo "tag holds no version: $tag" >&2
  exit 1
fi

here=$(cd "$(dirname "$0")" && pwd)
exec python3 "$here/update_manifest.py" \
  --version "$version" \
  --seq "$seq" \
  --base-url "https://github.com/${repo}/releases/download/${tag}" \
  --target "x86_64-unknown-linux-gnu=${dir}/fleetd-x86_64-unknown-linux-musl.tar.gz" \
  --target "aarch64-unknown-linux-gnu=${dir}/fleetd-aarch64-unknown-linux-musl.tar.gz" \
  --out "$out"
