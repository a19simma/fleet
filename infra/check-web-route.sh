#!/bin/sh
set -eu

dir=${1:-$(dirname "$0")}

if command -v kubectl >/dev/null 2>&1; then
  out=$(kubectl kustomize "$dir")
elif command -v kustomize >/dev/null 2>&1; then
  out=$(kustomize build "$dir")
else
  echo "check-web-route: neither kubectl nor kustomize found" >&2
  exit 2
fi

fail=0
bad() {
  echo "check-web-route: $1" >&2
  fail=1
}

route=$(printf '%s\n' "$out" | awk -v RS='---\n' '/kind: HTTPRoute/')
[ -n "$route" ] || bad "no HTTPRoute rendered"

host=$(printf '%s\n' "$route" | awk '/^  hostnames:/{f=1; next} f && /^  - /{sub(/^  - /, ""); print; exit}')
[ -n "$host" ] || bad "HTTPRoute has no hostname"

printf '%s\n' "$route" | grep -q 'name: Strict-Transport-Security' || bad "HTTPRoute does not set Strict-Transport-Security"
printf '%s\n' "$route" | grep -Eq 'value: max-age=[1-9][0-9]{6,}' || bad "HSTS max-age is below 1000000 seconds"
printf '%s\n' "$route" | grep -Eq '^ +port: 7070$' || bad "HTTPRoute backend is not port 7070"
printf '%s\n' "$route" | grep -Eq '^ +name: fleet-server$' || bad "HTTPRoute backend is not Service fleet-server"

env_value() {
  printf '%s\n' "$out" | awk -v n="$1" '$0 ~ "- name: " n "$" {getline; sub(/^ *value: /, ""); gsub(/"/, ""); print; exit}'
}
rp=$(env_value FLEET_WEB_RP_ID)
origin=$(env_value FLEET_WEB_ORIGIN)
[ -n "$rp" ] || bad "Deployment lacks FLEET_WEB_RP_ID"
[ -n "$origin" ] || bad "Deployment lacks FLEET_WEB_ORIGIN"
[ "$rp" = "$host" ] || bad "FLEET_WEB_RP_ID ($rp) differs from the route host ($host)"
[ "$origin" = "https://$host" ] || bad "FLEET_WEB_ORIGIN ($origin) is not https://$host"

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "check-web-route: ok"
