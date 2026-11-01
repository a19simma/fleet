# infra

Kubernetes manifests for fleet-server. An Argo CD Application in the cluster operator's own repo tracks this directory on `main` and applies it. See [ADR-0025](../docs/adr/0025-fleet-infra-directory-and-scoped-deploy.md).

## Contents

- `deployment.yaml`: the fleet-server Deployment in namespace `fleet-server`.
- `service.yaml`: a ClusterIP Service for the gRPC port (7070) and the health port (7072).
- `kustomization.yaml`: lists the manifests and pins the image `ghcr.io/a19simma/fleet-server` to tag 0.3.2. That tag is a baseline floor.
- `master-key-generator.yaml` and `master-key-externalsecret.yaml`: an external-secrets Password generator and an ExternalSecret that create Secret `fleet-master-key` once. See Master key. `bootstrap-password-generator.yaml` and `bootstrap-password-externalsecret.yaml` do the same for the bootstrap password. See Bootstrap password.
- `check-master-key-kind.sh`: creates a uniquely named kind cluster, installs external-secrets, applies both objects, and proves a restricted pod reads the key ring file, the mount is read-only, and the key survives a forced sync, a controller restart and an ExternalSecret recreate. It deletes only its own cluster. Needs `kind`, `kubectl`, `helm` and network access.
- `check-kinds.sh`: renders the kustomization and fails on any kind outside Deployment, Service, ExternalSecret, Password, and on any container or initContainer in a Deployment that lacks requests for cpu, memory and ephemeral-storage or limits for memory and ephemeral-storage. A cpu limit is allowed but not required.
- `test-check-kinds.sh`: proves the check rejects a Role, Namespace, HTTPRoute, GRPCRoute, Secret, non-ClusterIP Service, other namespace, `hostNetwork`, `hostPID`, `hostIPC`, `hostPath`, privileged containers and containers missing a cpu, memory or ephemeral-storage request or a memory or ephemeral-storage limit. It also proves a container with or without a cpu limit is accepted.

## Allowed kinds

Deployment, Service, ExternalSecret, Password (the external-secrets generator), in namespace `fleet-server`. The Argo CD project that owns the Application allows nothing else, and CI runs `check-kinds.sh` so a change outside that set fails before merge. The check also rejects Service shapes `NodePort`, `LoadBalancer`, `ExternalName` and `externalIPs`.

The check does not cover `runAsUser`, `capabilities.add` or `serviceAccountName`. Pod Security `restricted` and the operator cover those.

## Contract with the cluster operator

The operator owns everything this directory leaves out.

- Namespace `fleet-server` exists, with Pod Security `restricted`, a resource quota and a network policy. The quota requires cpu requests and memory and ephemeral-storage limits on every container, and does not require a cpu limit.
- Secret `fleet-server-secrets` exists in that namespace with keys `FLEET_DATABASE_URL` and `FLEET_TOKEN`. The key `FLEET_CLIENT_TOKEN` is optional: the Deployment reads it with `optional: true`, and without it the server leaves `FleetQuery` and `FleetJobs` closed (ADR-0023).
- Optional retention settings, set as plain `env` entries in the Deployment when the defaults do not fit: `FLEET_EVENTS_RETENTION_DAYS` (default 90), `FLEET_SUMMARIES_RETENTION_DAYS` (default 365, not below the events value) and `FLEET_RETENTION_INTERVAL_SECS` (default 3600, minimum 60). The server prunes job events and summaries of finished jobs on that schedule and keeps job rows and transcripts. An invalid value stops startup.
- Optional CI retry: `FLEET_MAX_CI_RETRIES` (0 to 5, default 0, which turns it off). When a job's pull request CI fails, the server submits up to that many fix jobs on the same branch (ADR-0028). An invalid value stops startup.
- The external-secrets operator runs in the cluster and the Argo CD project allows `ExternalSecret` (`external-secrets.io`) and `Password` (`generators.external-secrets.io`) in the namespace.
- A Postgres 17 database and a role for the server exist, and `FLEET_DATABASE_URL` points at them.
- A Gateway named `fleet` in namespace `fleet-server` with an HTTPS listener named `https` and its certificate exist. The Gateway, the host and TLS belong to the operator.
- This repo ships no routes. The operator owns the HTTPRoute and the GRPCRoute, in its own repo under the Argo project `routes`, along with the Gateway, the host and TLS.
- The operator patches `FLEET_WEB_RP_ID` (the bare host) and `FLEET_WEB_ORIGIN` (`https://` plus the host) on the Deployment so both match the route host. The Deployment keeps the placeholders `fleet.example.com` and `https://fleet.example.com`. The web UI needs both set.
- Both routes share one host and one listener. The Gateway API spec says an implementation MAY reject one of them (the oldest wins). Cilium behaviour is unverified here. The operator checks the `Accepted` status of each route.
- The gateway must redirect HTTP to HTTPS. Browsers honour `Strict-Transport-Security` only when it arrives over HTTPS, so the header does not protect a first plain HTTP request.
- Header and idle timeouts for the shared HTTP/1.1 and h2c port (SEC-001) are not route fields. The operator sets them in the gateway implementation's policy, for example a client traffic policy with a client request header timeout and an idle timeout, and keeps them short enough to bound slow clients.

## Master key

ADR-0040 keeps the credential master key in a file. The Deployment mounts Secret `fleet-master-key` read-only at `/etc/fleet/master-key` and sets `FLEET_MASTER_KEY_FILE=/etc/fleet/master-key/keyring`. The file holds one key ring line, `k1:` followed by 64 hex characters. The first line is the active key.

The Password generator makes 32 random characters under the key `password`. The ExternalSecret template writes `keyring` as `k1:` plus the sha256 of that password, which is 64 hex characters. The installed operator's Password CRD has no `encoding`, `prefix` or `secretKeys` fields, so the template does that work. The ExternalSecret sets `refreshInterval: "0s"`, `refreshPolicy: CreatedOnce` and `creationPolicy: Orphan`, so the Secret is created once and never rewritten, and it outlives the ExternalSecret. A regenerated key would make every stored credential unreadable.

Sources, read 2026-10-29:

- Official docs, [Generator guide](https://external-secrets.io/latest/guides/generator/): "The generator does not keep track of the produced values. Every invocation produces a new set of values." So stability comes from the ExternalSecret settings alone.
- Source code, [externalsecret_types.go](https://github.com/external-secrets/external-secrets/blob/main/apis/externalsecrets/v1/externalsecret_types.go): `refreshInterval` "May be set to "0s" to fetch and create it once". `refreshPolicy` `CreatedOnce` "Creates the Secret only if it does not exist and does not update it thereafter". `creationPolicy` `Orphan` "creates the Secret and does not set the ownerReference. I.e. it will be orphaned after the deletion of the ExternalSecret."

Verified in kind with `check-master-key-kind.sh` against chart `external-secrets` 2.14.0: the key file is unchanged and the Secret uid is the same after a forced sync annotation, a controller restart and an ExternalSecret delete and recreate. Unverified: behaviour under a different operator version, and whether a new CRD default would change the semantics. The live cluster rejected the generator's `encoding`, `prefix` and `secretKeys`; the first deploy produced a key named `password` and the server refused to start. Pin the operator version in the operator's repo.

Rotation, backup and restore steps are in [docs/credential-key-runbook.md](../docs/credential-key-runbook.md).

If the Secret `fleet-master-key` is deleted outside the generator flow, the ExternalSecret (`CreatedOnce`) mints a new key and every stored credential becomes unreadable. Back the key up first. The runbook covers Back up, Rotate, and Restore with and without the key. The key is the sha256 of a 32 character generator password, so its entropy is that of the password. With about 66 symbols that is roughly 190 bits, and the generator charset is unverified.

## Bootstrap password

ADR-0042 lets the first admin enroll a passkey with a one-time bootstrap password. `bootstrap-password-generator.yaml` and `bootstrap-password-externalsecret.yaml` create Secret `fleet-bootstrap-password` (key `password`, 32 generator characters) once, with the same `CreatedOnce` and `Orphan` settings as the master key. The Deployment passes it as `FLEET_BOOTSTRAP_PASSWORD` (optional, so a missing Secret falls back to the logged setup URL). The server hashes it with argon2id at startup and never stores the plaintext. The first passkey revokes it in the same transaction; a revoked password stays revoked, so a restart or a regenerated Secret does not re-arm it. Read it once with `kubectl -n fleet-server get secret fleet-bootstrap-password -o jsonpath='{.data.password}'` and delete the Secret after setup.

`FLEET_TRUSTED_PROXY_HOPS=1` makes the server take the client address from the last `X-Forwarded-For` entry, which the gateway appends. Set it to the number of trusted proxies in front of the server; `0` uses the TCP peer. Unverified: that the live gateway appends the peer to `X-Forwarded-For` in this form.

The operator must enable etcd encryption at rest. Without it the Secret sits in etcd in the clear (ADR-0040).

## Server variables

The Deployment sets `FLEET_LISTEN`, `FLEET_HEALTH_LISTEN`, `FLEET_DATABASE_URL`, `FLEET_TOKEN`, `FLEET_CLIENT_TOKEN`, `FLEET_WEB_RP_ID`, `FLEET_WEB_ORIGIN` and `FLEET_MASTER_KEY_FILE`. Its only volume is the master key. These fleet-server variables are not set by default:

| Variable | Meaning |
| --- | --- |
| `FLEET_UPDATE_MANIFEST` | path of the signed update manifest. The signature is the file of the same name with `.minisig` appended. Unset or empty means no manifest. The Deployment mounts no manifest file, and ConfigMap and Secret are outside the allowed kinds, so delivering the manifest to the pod is an open item for the operator. |
| `FLEET_ALLOW_PROFILE_TOOLS` | `true` or `false`, default `false`, empty counts as `false`, anything else stops startup. While `false` the server refuses a Profile with `tools`. Tools are accepted only in TOML Profile content. A Box also needs the `[mise]` section, see [deploy/README.md](../deploy/README.md#bundled-mise-and-the-mise-section). |

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
