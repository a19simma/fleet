# infra

Kubernetes manifests for fleet-server. An Argo CD Application in the cluster operator's own repo tracks this directory on `main` and applies it. See [ADR-0025](../docs/adr/0025-fleet-infra-directory-and-scoped-deploy.md).

## Contents

- `deployment.yaml`: the fleet-server Deployment in namespace `fleet-server`.
- `service.yaml`: a ClusterIP Service for the gRPC port (7070) and the health port (7072).
- `kustomization.yaml`: lists both and pins the image `ghcr.io/a19simma/fleet-server` to tag 0.2.1. That tag is a baseline floor.
- `master-key-generator.yaml` and `master-key-externalsecret.yaml`: an external-secrets Password generator and an ExternalSecret that create Secret `fleet-master-key` once. See Master key.
- `httproute.yaml`: HTTPRoute `fleet-server` on one host. It sends every path to Service port 7070 (pages under `/` and `/static/style.css`, gRPC under `/fleet.v1.`), sets `Strict-Transport-Security: max-age=31536000` on responses, and disables the route request timeout so gRPC streams survive. The host is the placeholder `fleet.example.com`.
- `check-web-route.sh`: renders the kustomization and fails unless the HTTPRoute sets HSTS, targets port 7070, and `FLEET_WEB_RP_ID` and `FLEET_WEB_ORIGIN` equal the route host and `https://` plus the host.
- `check-web-kind.sh`: creates a kind cluster, installs Envoy Gateway, creates a Gateway `fleet` with a self-signed HTTPS listener, applies `service.yaml` and `httproute.yaml` over a stand-in backend, then fetches the page over HTTP/2 and TLS, checks HSTS, and POSTs a gRPC call to `/fleet.v1.` and checks `grpc-status`. The stand-in is Caddy, not fleet-server: it proves gateway routing, TLS, h2c to the backend and the HSTS header, and does not prove the server's own handlers. Needs `kind`, `kubectl`, `helm`, `openssl` and network access. Set `ENVOY_GATEWAY_VERSION` to pin the chart.
- `check-master-key-kind.sh`: creates a uniquely named kind cluster, installs external-secrets, applies both objects, and proves a restricted pod reads the key ring file, the mount is read-only, and the key survives a forced sync, a controller restart and an ExternalSecret recreate. It deletes only its own cluster. Needs `kind`, `kubectl`, `helm` and network access.
- `check-kinds.sh`: renders the kustomization and fails on any kind outside Deployment, Service, ExternalSecret, Password and HTTPRoute, and on any container or initContainer in a Deployment that lacks requests for cpu, memory and ephemeral-storage or limits for memory and ephemeral-storage. A cpu limit is allowed but not required.
- `test-check-kinds.sh`: proves the check rejects a Role, Namespace, Secret, non-ClusterIP Service, other namespace, `hostNetwork`, `hostPID`, `hostIPC`, `hostPath`, privileged containers and containers missing a cpu, memory or ephemeral-storage request or a memory or ephemeral-storage limit. It also proves a container with or without a cpu limit is accepted.

## Allowed kinds

Deployment, Service, ExternalSecret, Password (the external-secrets generator) and HTTPRoute (`gateway.networking.k8s.io`), in namespace `fleet-server`. The Argo CD project that owns the Application allows nothing else, and CI runs `check-kinds.sh` so a change outside that set fails before merge. The check also rejects Service shapes `NodePort`, `LoadBalancer`, `ExternalName` and `externalIPs`.

The check does not cover `runAsUser`, `capabilities.add` or `serviceAccountName`. Pod Security `restricted` and the operator cover those.

## Contract with the cluster operator

The operator owns everything this directory leaves out.

- Namespace `fleet-server` exists, with Pod Security `restricted`, a resource quota and a network policy. The quota requires cpu requests and memory and ephemeral-storage limits on every container, and does not require a cpu limit.
- Secret `fleet-server-secrets` exists in that namespace with keys `FLEET_DATABASE_URL` and `FLEET_TOKEN`. The key `FLEET_CLIENT_TOKEN` is optional: the Deployment reads it with `optional: true`, and without it the server leaves `FleetQuery` and `FleetJobs` closed (ADR-0023).
- Optional retention settings, set as plain `env` entries in the Deployment when the defaults do not fit: `FLEET_EVENTS_RETENTION_DAYS` (default 90), `FLEET_SUMMARIES_RETENTION_DAYS` (default 365, not below the events value) and `FLEET_RETENTION_INTERVAL_SECS` (default 3600, minimum 60). The server prunes job events and summaries of finished jobs on that schedule and keeps job rows and transcripts. An invalid value stops startup.
- Optional CI retry: `FLEET_MAX_CI_RETRIES` (0 to 5, default 0, which turns it off). When a job's pull request CI fails, the server submits up to that many fix jobs on the same branch (ADR-0028). An invalid value stops startup.
- The external-secrets operator runs in the cluster and the Argo CD project allows `ExternalSecret` (`external-secrets.io`) and `Password` (`generators.external-secrets.io`) in the namespace.
- A Postgres 17 database and a role for the server exist, and `FLEET_DATABASE_URL` points at them.
- A Gateway named `fleet` in namespace `fleet-server` with an HTTPS listener named `https` and its certificate exist. The Gateway belongs to the operator, and so does the Argo CD project permission for `HTTPRoute`.
- The operator sets the real host in its own Application with a kustomize patch of `/spec/hostnames/0` on HTTPRoute `fleet-server`. The kustomization copies that value into `FLEET_WEB_RP_ID` (the bare host) and `FLEET_WEB_ORIGIN` (`https://` plus the host) after patches apply, so the three always match. The repo keeps only the placeholder host.
- Header and idle timeouts for the shared HTTP/1.1 and h2c port (SEC-001) are not HTTPRoute fields. The operator sets them in the gateway implementation's policy, for example a client traffic policy with a client request header timeout and an idle timeout, and keeps them short enough to bound slow clients.

## Master key

ADR-0040 keeps the credential master key in a file. The Deployment mounts Secret `fleet-master-key` read-only at `/etc/fleet/master-key` and sets `FLEET_MASTER_KEY_FILE=/etc/fleet/master-key/keyring`. The file holds one key ring line, `k1:` followed by 64 hex characters. The first line is the active key.

The Password generator makes the value: `length: 32` with `encoding: hex` gives 64 hex characters, and `prefix: "k1:"` adds the key id. The ExternalSecret sets `refreshInterval: "0s"`, `refreshPolicy: CreatedOnce` and `creationPolicy: Orphan`, so the Secret is created once and never rewritten, and it outlives the ExternalSecret. A regenerated key would make every stored credential unreadable.

Sources, read 2026-10-29:

- Official docs, [Generator guide](https://external-secrets.io/latest/guides/generator/): "The generator does not keep track of the produced values. Every invocation produces a new set of values." So stability comes from the ExternalSecret settings alone.
- Source code, [externalsecret_types.go](https://github.com/external-secrets/external-secrets/blob/main/apis/externalsecrets/v1/externalsecret_types.go): `refreshInterval` "May be set to "0s" to fetch and create it once". `refreshPolicy` `CreatedOnce` "Creates the Secret only if it does not exist and does not update it thereafter". `creationPolicy` `Orphan` "creates the Secret and does not set the ownerReference. I.e. it will be orphaned after the deletion of the ExternalSecret."
- Official docs, [Password generator](https://external-secrets.io/latest/api/generator/password/) (raw page): "The prefix and suffix are added after `encoding`" and the hex example turns a 16 character password into 32 hex characters.

Verified in kind with `check-master-key-kind.sh` against chart `external-secrets` 2.14.0: the key file is unchanged and the Secret uid is the same after a forced sync annotation, a controller restart and an ExternalSecret delete and recreate. Unverified: behaviour under a different operator version, and whether a new CRD default would change the semantics. Pin the operator version in the operator's repo.

The operator must enable etcd encryption at rest. Without it the Secret sits in etcd in the clear (ADR-0040).

## Image tag

The Argo CD Image Updater with the `argocd` write-back method overrides the kustomize image tag on the Application. It needs no git write access. The `newTag` in `kustomization.yaml` is the lowest version a fresh sync uses.

## Trust model

A push to `main` here deploys code into the `fleet-server` namespace. A Deployment can read the namespace Secret and connect to the database. Protect `main`: require review and passing checks, and restrict who can push.

Pod Security `restricted`, the quota and the network policy sit in the operator's repo to limit what a bad Deployment can do. The pod spec here already meets `restricted`: non-root, seccomp `RuntimeDefault`, no privilege escalation, all capabilities dropped, read-only root filesystem and no service account token.

## Local check

```sh
infra/check-kinds.sh
infra/test-check-kinds.sh
```

Both need `kubectl` or `kustomize` on the path. The test writes scratch copies into a fresh `mktemp -d` directory under `$SCRATCH`, default `${TMPDIR:-/tmp}`. The test never deletes it, so the caller cleans up.
