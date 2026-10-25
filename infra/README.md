# infra

Kubernetes manifests for fleet-server. An Argo CD Application in the cluster operator's own repo tracks this directory on `main` and applies it. See [ADR-0025](../docs/adr/0025-fleet-infra-directory-and-scoped-deploy.md).

## Contents

- `deployment.yaml`: the fleet-server Deployment in namespace `fleet-server`.
- `service.yaml`: a ClusterIP Service for the gRPC port (7070) and the health port (7072).
- `kustomization.yaml`: lists both and pins the image `ghcr.io/a19simma/fleet-server` to tag 0.2.1. That tag is a baseline floor.
- `check-kinds.sh`: renders the kustomization and fails on any kind outside Deployment and Service, and on any container or initContainer in a Deployment that lacks requests for cpu, memory and ephemeral-storage or limits for memory and ephemeral-storage. A cpu limit is allowed but not required.
- `test-check-kinds.sh`: proves the check rejects a Role, Namespace, Secret, non-ClusterIP Service, other namespace, `hostNetwork`, `hostPID`, `hostIPC`, `hostPath`, privileged containers and containers missing a cpu, memory or ephemeral-storage request or a memory or ephemeral-storage limit. It also proves a container with or without a cpu limit is accepted.

## Allowed kinds

Deployment and Service, in namespace `fleet-server`. The Argo CD project that owns the Application allows nothing else, and CI runs `check-kinds.sh` so a change outside that set fails before merge. The check also rejects Service shapes `NodePort`, `LoadBalancer`, `ExternalName` and `externalIPs`.

The check does not cover `runAsUser`, `capabilities.add` or `serviceAccountName`. Pod Security `restricted` and the operator cover those.

## Contract with the cluster operator

The operator owns everything this directory leaves out.

- Namespace `fleet-server` exists, with Pod Security `restricted`, a resource quota and a network policy. The quota requires cpu requests and memory and ephemeral-storage limits on every container, and does not require a cpu limit.
- Secret `fleet-server-secrets` exists in that namespace with keys `FLEET_DATABASE_URL` and `FLEET_TOKEN`. The key `FLEET_CLIENT_TOKEN` is optional: the Deployment reads it with `optional: true`, and without it the server leaves `FleetQuery` and `FleetJobs` closed (ADR-0023).
- A Postgres 17 database and a role for the server exist, and `FLEET_DATABASE_URL` points at them.
- The route and gateway that expose port 7070 belong to the operator. The route holds a private hostname, so it does not live in this repo.

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
