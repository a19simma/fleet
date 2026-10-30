#!/bin/sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
name=${KIND_CLUSTER:-fleet-web-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')}
ns=fleet-server
ctx=kind-$name
eg_version=${ENVOY_GATEWAY_VERSION:-v1.5.0}
host=${ROUTE_HOST:-$(awk '/^  hostnames:/{f=1; next} f && /^    - /{sub(/^    - /, ""); print; exit}' "$here/httproute.yaml")}
scratch=
created=0

cleanup() {
  if [ "$created" = 1 ]; then
    kind delete cluster --name "$name" >/dev/null 2>&1 || true
  fi
  if [ -n "$scratch" ]; then
    rm -rf "$scratch"
  fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM

scratch=$(mktemp -d "${TMPDIR:-/tmp}/fleet-web-kind.XXXXXX")

k() { kubectl --context "$ctx" -n "$ns" "$@"; }
fail() { echo "check-web-kind: $1" >&2; exit 1; }

"$here/check-web-route.sh" "$here" >/dev/null || fail "static render check failed"
[ -n "$host" ] || fail "no route host"

echo "check-web-kind: cluster $name host $host"
if kind get clusters 2>/dev/null | grep -Fxq -- "$name"; then
  fail "kind cluster $name already exists, refusing to touch it"
fi
kind create cluster --name "$name" --wait 120s >/dev/null
created=1

helm --kube-context "$ctx" install eg oci://docker.io/envoyproxy/gateway-helm \
  --version "$eg_version" -n envoy-gateway-system --create-namespace --wait --timeout 300s >&2 || fail "envoy gateway install failed"

kubectl --context "$ctx" create namespace "$ns" >/dev/null

OPENSSL_CONF=/dev/null openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$host" \
  -addext "subjectAltName=DNS:$host" -keyout "$scratch/tls.key" -out "$scratch/tls.crt" >/dev/null 2>&1 || fail "openssl could not make a certificate"
k create secret tls fleet-tls --cert="$scratch/tls.crt" --key="$scratch/tls.key" >/dev/null

cat <<YAML | kubectl --context "$ctx" apply -f - >/dev/null
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: eg
spec:
  controllerName: gateway.envoyproxy.io/gatewayclass-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: fleet
  namespace: $ns
spec:
  gatewayClassName: eg
  listeners:
    - name: https
      port: 443
      protocol: HTTPS
      hostname: $host
      tls:
        mode: Terminate
        certificateRefs:
          - name: fleet-tls
YAML

cat <<'YAML' | k apply -f - >/dev/null
apiVersion: v1
kind: ConfigMap
metadata:
  name: backend-config
data:
  Caddyfile: |
    {
      auto_https off
      servers {
        protocols h1 h2c
      }
    }
    :7070 {
      handle /fleet.v1.* {
        header Content-Type application/grpc
        header grpc-status 16
        respond 200
      }
      handle /static/style.css {
        header Content-Type text/css
        respond "body{}" 200
      }
      handle / {
        header Content-Type text/html
        respond "<html>fleet</html>" 200
      }
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fleet-server
  labels:
    app: fleet-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: fleet-server
  template:
    metadata:
      labels:
        app: fleet-server
    spec:
      containers:
        - name: backend
          image: caddy:2.10-alpine
          args: ["caddy", "run", "--config", "/etc/caddy/Caddyfile"]
          ports:
            - name: grpc
              containerPort: 7070
          volumeMounts:
            - name: config
              mountPath: /etc/caddy
      volumes:
        - name: config
          configMap:
            name: backend-config
YAML
k apply -f "$here/service.yaml" -f "$here/httproute.yaml" >/dev/null
if [ "$host" != "$(awk '/^  hostnames:/{f=1; next} f && /^    - /{sub(/^    - /, ""); print; exit}' "$here/httproute.yaml")" ]; then
  k patch httproute fleet-server --type=json -p "[{\"op\":\"replace\",\"path\":\"/spec/hostnames/0\",\"value\":\"$host\"}]" >/dev/null
fi

k wait deployment/fleet-server --for=condition=Available --timeout=180s >/dev/null
k wait gateway/fleet --for=condition=Accepted --timeout=180s >/dev/null
k wait httproute/fleet-server --for=jsonpath='{.status.parents[0].conditions[?(@.type=="Accepted")].status}'=True --timeout=120s >/dev/null

svc=$(kubectl --context "$ctx" -n envoy-gateway-system get svc \
  -l gateway.envoyproxy.io/owning-gateway-name=fleet,gateway.envoyproxy.io/owning-gateway-namespace=$ns \
  -o jsonpath='{.items[0].metadata.name}')
[ -n "$svc" ] || fail "no envoy service for the gateway"
addr=$(kubectl --context "$ctx" -n envoy-gateway-system get svc "$svc" -o jsonpath='{.spec.clusterIP}')

kubectl --context "$ctx" -n envoy-gateway-system wait deployment -l gateway.envoyproxy.io/owning-gateway-name=fleet --for=condition=Available --timeout=180s >/dev/null
sleep 5
page=$(kubectl --context "$ctx" -n "$ns" run curl-page --rm -i --restart=Never --quiet \
  --image=curlimages/curl:8.15.0 --command -- \
  curl -sk --http2 --resolve "$host:443:$addr" -D - "https://$host/" ) || fail "page fetch failed"
printf '%s' "$page" | grep -qi '^HTTP/2 200' || fail "page is not HTTP/2 200 over TLS"
printf '%s' "$page" | grep -qi '^strict-transport-security: max-age=' || fail "page lacks HSTS"
printf '%s' "$page" | grep -q 'fleet' || fail "page body missing"
echo "ok: HTTPS page served, HSTS present"

rpc=$(kubectl --context "$ctx" -n "$ns" run curl-rpc --rm -i --restart=Never --quiet \
  --image=curlimages/curl:8.15.0 --command -- \
  curl -sk --http2 --resolve "$host:443:$addr" -D - -o /dev/null -X POST \
  -H 'content-type: application/grpc' -H 'te: trailers' --data-binary '' \
  "https://$host/fleet.v1.FleetQuery/ListBoxes") || fail "grpc call failed"
printf '%s' "$rpc" | grep -qi '^grpc-status:' || fail "grpc call returned no grpc-status"
printf '%s' "$rpc" | grep -qi '^content-type: application/grpc' || fail "grpc call returned no grpc content type"
echo "ok: gRPC call on the same host returned grpc-status"

kind delete cluster --name "$name" >/dev/null
created=0
echo "check-web-kind: cluster $name deleted"
