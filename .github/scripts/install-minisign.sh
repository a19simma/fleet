#!/usr/bin/env bash
set -euo pipefail

version="0.12"
sha256="9a599b48ba6eb7b1e80f12f36b94ceca7c00b7a5173c95c3efc88d9822957e73"
asset="minisign-${version}-linux.tar.gz"

case "$(uname -m)" in
  x86_64) arch="x86_64" ;;
  aarch64 | arm64) arch="aarch64" ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/minisign.XXXXXX")"
curl -fsSL --retry 3 -o "$dir/$asset" \
  "https://github.com/jedisct1/minisign/releases/download/${version}/${asset}"
echo "${sha256}  $dir/$asset" | sha256sum -c -
tar -xzf "$dir/$asset" -C "$dir"
chmod +x "$dir/minisign-linux/$arch/minisign"
echo "$dir/minisign-linux/$arch" >> "${GITHUB_PATH:-/dev/null}"
"$dir/minisign-linux/$arch/minisign" -v
