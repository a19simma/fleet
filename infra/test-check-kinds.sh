#!/bin/sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
base=${SCRATCH:-${TMPDIR:-/tmp}}
mkdir -p "$base"
scratch=$(mktemp -d "$base/fleet-infra-check.XXXXXX")
failures=0

fresh() {
  d="$scratch/$1"
  mkdir -p "$d"
  cp "$here/kustomization.yaml" "$here/deployment.yaml" "$here/service.yaml" "$d/"
  printf '%s\n' "$d"
}

add_resource() {
  insert_after '^  - service.yaml$' '  - extra.yaml' "$1/kustomization.yaml" >"$1/kustomization.next"
  cp "$1/kustomization.next" "$1/kustomization.yaml"
}

expect_fail() {
  if msg=$("$here/check-kinds.sh" "$1" 2>&1); then
    echo "FAIL: $2 was accepted" >&2
    failures=$((failures + 1))
  elif printf '%s\n' "$msg" | grep -q "^check-kinds: $3"; then
    echo "ok: $2 rejected"
  else
    echo "FAIL: $2 rejected for another reason: $msg" >&2
    failures=$((failures + 1))
  fi
}

insert_after() {
  awk -v pat="$1" -v add="$2" '{ print } $0 ~ pat { print add }' "$3"
}

d=$(fresh baseline)
if "$here/check-kinds.sh" "$d" >/dev/null 2>&1; then
  echo "ok: baseline without limits.cpu accepted"
else
  echo "FAIL: baseline without limits.cpu rejected" >&2
  failures=$((failures + 1))
fi

d=$(fresh role)
cat >"$d/extra.yaml" <<'YAML'
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: x
  namespace: fleet-server
rules: []
YAML
add_resource "$d"
expect_fail "$d" "Role" "kind Role"

d=$(fresh namespace)
cat >"$d/extra.yaml" <<'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: other
YAML
add_resource "$d"
expect_fail "$d" "Namespace" "kind Namespace"

d=$(fresh secret)
cat >"$d/extra.yaml" <<'YAML'
apiVersion: v1
kind: Secret
metadata:
  name: x
  namespace: fleet-server
YAML
add_resource "$d"
expect_fail "$d" "Secret" "kind Secret"

for t in NodePort LoadBalancer ExternalName; do
  d=$(fresh "svc-$t")
  sed "s/type: ClusterIP/type: $t/" "$here/service.yaml" >"$d/service.yaml"
  expect_fail "$d" "Service type $t" "Service type\|Service externalIPs"
done

d=$(fresh other-namespace)
sed 's/namespace: fleet-server/namespace: other/' "$here/service.yaml" >"$d/service.yaml"
expect_fail "$d" "Service in another namespace" "namespace other"

d=$(fresh no-namespace)
sed '/namespace: fleet-server/d' "$here/service.yaml" >"$d/service.yaml"
expect_fail "$d" "Service without namespace" "every object"

for field in hostNetwork hostPID hostIPC; do
  d=$(fresh "pod-$field")
  insert_after '^    spec:$' "      $field: true" "$here/deployment.yaml" >"$d/deployment.yaml"
  expect_fail "$d" "pod with $field" "pod sets"
done

d=$(fresh hostpath)
insert_after '^    spec:$' "      volumes: [{name: v, hostPath: {path: /etc}}]" "$here/deployment.yaml" >"$d/deployment.yaml"
expect_fail "$d" "hostPath volume" "pod uses"

d=$(fresh privileged)
insert_after 'allowPrivilegeEscalation: false' "            privileged: true" "$here/deployment.yaml" >"$d/deployment.yaml"
expect_fail "$d" "privileged container" "pod sets"

d=$(fresh with-limits-cpu)
insert_after '^            limits:$' "              cpu: 500m" "$here/deployment.yaml" >"$d/deployment.yaml"
if "$here/check-kinds.sh" "$d" >/dev/null 2>&1; then
  echo "ok: container with limits.cpu accepted"
else
  echo "FAIL: container with limits.cpu rejected" >&2
  failures=$((failures + 1))
fi

for spec in "requests.cpu|^              cpu: 50m$|resources.requests.cpu" \
  "limits.ephemeral-storage|^              ephemeral-storage: 128Mi$|resources.limits.ephemeral-storage" \
  "requests.memory|^              memory: 64Mi$|resources.requests.memory" \
  "limits.memory|^              memory: 256Mi$|resources.limits.memory" \
  "requests.ephemeral-storage|^              ephemeral-storage: 64Mi$|resources.requests.ephemeral-storage"; do
  name=${spec%%|*}
  rest=${spec#*|}
  pat=${rest%%|*}
  want=${rest#*|}
  d=$(fresh "res-$name")
  sed "/$pat/d" "$here/deployment.yaml" >"$d/deployment.yaml"
  expect_fail "$d" "container without $name" "container fleet-server lacks $want"
done

d=$(fresh init-container)
insert_after '^    spec:$' "      initContainers: [{name: init, image: busybox, resources: {requests: {cpu: 1m}}}]" "$here/deployment.yaml" >"$d/deployment.yaml"
expect_fail "$d" "initContainer without resources" "container init lacks"

if [ "$failures" -ne 0 ]; then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "all checks passed"
