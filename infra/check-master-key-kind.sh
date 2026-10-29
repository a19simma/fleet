#!/bin/sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
name=${KIND_CLUSTER:-fleet-mk-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')}
ns=fleet-server
ctx=kind-$name
chart_version=${ESO_CHART_VERSION:-}

k() { kubectl --context "$ctx" -n "$ns" "$@"; }
fail() { echo "check-master-key-kind: $1" >&2; exit 1; }

echo "check-master-key-kind: cluster $name"
kind create cluster --name "$name" --wait 120s >/dev/null

helm repo add external-secrets https://charts.external-secrets.io >/dev/null
helm repo update external-secrets >/dev/null
helm --kube-context "$ctx" upgrade --install external-secrets external-secrets/external-secrets \
  --namespace external-secrets --create-namespace --wait --timeout 300s \
  ${chart_version:+--version "$chart_version"} >/dev/null

kubectl --context "$ctx" create namespace "$ns" >/dev/null
kubectl --context "$ctx" label namespace "$ns" pod-security.kubernetes.io/enforce=restricted >/dev/null

k apply -f "$here/master-key-generator.yaml" -f "$here/master-key-externalsecret.yaml" >/dev/null
k wait externalsecret/fleet-master-key --for=condition=Ready --timeout=120s >/dev/null

cat <<'YAML' | k apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: key-reader
spec:
  automountServiceAccountToken: false
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    fsGroup: 65532
    seccompProfile:
      type: RuntimeDefault
  volumes:
    - name: master-key
      secret:
        secretName: fleet-master-key
        defaultMode: 0440
  containers:
    - name: reader
      image: busybox:1.37
      command: ["sleep", "600"]
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
      volumeMounts:
        - name: master-key
          mountPath: /etc/fleet/master-key
          readOnly: true
YAML
k wait pod/key-reader --for=condition=Ready --timeout=120s >/dev/null

path=/etc/fleet/master-key/keyring
shape=$(k exec key-reader -- sh -c "head -n1 $path | grep -Ec '^[A-Za-z0-9_-]+:[0-9a-f]{64}\$'")
[ "$shape" = 1 ] || fail "first line of $path is not key_id:hex64"
echo "ok: pod reads $path, first line matches key_id:hex64"

if k exec key-reader -- sh -c "echo x >> $path" 2>/dev/null; then
  fail "mount is writable"
fi
echo "ok: mount is read-only"

digest() { k exec key-reader -- sha256sum "$path" | cut -d' ' -f1; }
secret_uid() { k get secret fleet-master-key -o jsonpath='{.metadata.uid}'; }
secret_rv() { k get secret fleet-master-key -o jsonpath='{.metadata.resourceVersion}'; }

before=$(digest)
uid_before=$(secret_uid)

k annotate externalsecret fleet-master-key force-sync="$(date +%s)" --overwrite >/dev/null
kubectl --context "$ctx" -n external-secrets rollout restart deployment/external-secrets >/dev/null
kubectl --context "$ctx" -n external-secrets rollout status deployment/external-secrets --timeout=180s >/dev/null
k delete externalsecret fleet-master-key >/dev/null
k apply -f "$here/master-key-externalsecret.yaml" >/dev/null
k wait externalsecret/fleet-master-key --for=condition=Ready --timeout=120s >/dev/null
k annotate externalsecret fleet-master-key force-sync="$(date +%s)" --overwrite >/dev/null
sleep 30

[ "$(secret_uid)" = "$uid_before" ] || fail "Secret was recreated"
[ "$(digest)" = "$before" ] || fail "key changed after force sync, controller restart and ExternalSecret recreate"
echo "ok: key unchanged after force sync, controller restart and ExternalSecret recreate"

kind delete cluster --name "$name" >/dev/null
echo "check-master-key-kind: cluster $name deleted"
