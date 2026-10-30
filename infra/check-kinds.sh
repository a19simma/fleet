#!/bin/sh
set -eu

dir=${1:-$(dirname "$0")}
allowed_ns=fleet-server

if command -v kubectl >/dev/null 2>&1; then
  out=$(kubectl kustomize "$dir")
elif command -v kustomize >/dev/null 2>&1; then
  out=$(kustomize build "$dir")
else
  echo "check-kinds: neither kubectl nor kustomize found" >&2
  exit 2
fi

fail=0
bad() {
  echo "check-kinds: $1" >&2
  fail=1
}

if [ -z "$out" ]; then
  bad "rendered output is empty"
fi

kinds=$(printf '%s\n' "$out" | sed -n 's/^kind:[[:space:]]*//p')
for k in $kinds; do
  case "$k" in
    Deployment | Service | ExternalSecret | Password | HTTPRoute) ;;
    *) bad "kind $k is not allowed, only Deployment, Service, ExternalSecret, Password and HTTPRoute" ;;
  esac
done

docs=$(printf '%s\n' "$out" | grep -c '^kind:' || true)
inns=$(printf '%s\n' "$out" | grep -c "^  namespace: $allowed_ns\$" || true)
if [ "$docs" -ne "$inns" ]; then
  bad "every object needs metadata.namespace $allowed_ns"
fi
if printf '%s\n' "$out" | grep -E '^[[:space:]]*namespace:' | grep -vE "namespace:[[:space:]]*$allowed_ns\$" >/dev/null; then
  bad "namespace other than $allowed_ns"
fi

if printf '%s\n' "$out" | grep -E '^  type:' | grep -vE '^  type:[[:space:]]*ClusterIP$' >/dev/null; then
  bad "Service type other than ClusterIP"
fi
if printf '%s\n' "$out" | grep -E '^  (externalIPs|externalName):' >/dev/null; then
  bad "Service externalIPs or externalName"
fi

if printf '%s\n' "$out" | grep -E '(hostNetwork|hostPID|hostIPC|privileged|allowPrivilegeEscalation):[[:space:]]*true' >/dev/null; then
  bad "pod sets hostNetwork, hostPID, hostIPC, privileged or allowPrivilegeEscalation"
fi
if printf '%s\n' "$out" | grep -E '(^|[[:space:]-])(hostPath|hostPort):' >/dev/null; then
  bad "pod uses a hostPath volume or hostPort"
fi

missing=$(printf '%s\n' "$out" | awk '
function indent(s) { match(s, /^ */); return RLENGTH }
function finish_container(   r, k, res) {
  if (!incont) return
  split("requests limits", res, " ")
  for (r = 1; r <= 2; r++) {
    split("cpu memory ephemeral-storage", k, " ")
    for (j = 1; j <= 3; j++) {
      if (res[r] == "limits" && k[j] == "cpu") continue
      if (!((res[r], k[j]) in have)) {
        pending = pending "container " cname " lacks resources." res[r] "." k[j] "\n"
      }
    }
  }
  delete have
  incont = 0
}
function finish_doc() {
  finish_container()
  if (kind == "Deployment") printf "%s", pending
  pending = ""
  kind = ""
  insec = 0
  sect = 0
}
/^---[[:space:]]*$/ { finish_doc(); next }
/^kind:/ { kind = $2 }
{
  line = $0
  if (line ~ /^[[:space:]]*$/) next
  ind = indent(line)
  if (insec == 1) {
    ci = ind
    insec = 2
  }
  if (insec == 2 && (ind < ci || (ind == ci && line !~ /^ *- /))) {
    finish_container()
    insec = 0
  }
  if (insec == 0 && line ~ /^ *(containers|initContainers):[[:space:]]*$/) {
    insec = 1
    next
  }
  if (insec == 2) {
    if (ind == ci && line ~ /^ *- /) {
      finish_container()
      incont = 1
      cname = "?"
      inres = 0
      cur = ""
      sub(/- /, "  ", line)
    }
    if (incont) {
      if (ind == ci + 2 && line ~ /^ *name:/) {
        n = line
        sub(/^ *name:[[:space:]]*/, "", n)
        cname = n
      }
      if (inres && indent(line) <= resind) inres = 0
      if (!inres && indent(line) == ci + 2 && line ~ /^ *resources:/) {
        inres = 1
        resind = ci + 2
        cur = ""
        next
      }
      if (inres) {
        t = line
        sub(/^ */, "", t)
        if (t ~ /^requests:/) cur = "requests"
        else if (t ~ /^limits:/) cur = "limits"
        else if (cur != "" && match(t, /^(cpu|memory|ephemeral-storage):/)) {
          key = substr(t, 1, RLENGTH - 1)
          val = substr(t, RLENGTH + 1)
          gsub(/[[:space:]\"]/, "", val)
          if (val != "") have[cur, key] = 1
        }
      }
    }
  }
}
END { finish_doc() }
')
if [ -n "$missing" ]; then
  printf '%s\n' "$missing" | while IFS= read -r m; do
    echo "check-kinds: $m" >&2
  done
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "check-kinds: ok"
