# Fleet infra directory and scoped deploy

Status: Accepted. Built: `infra/` holds the manifests and CI checks the allowed kinds. Amends ADR-0013.

ADR-0013 names Kubernetes and Argo CD as the deployment stack and leaves the deploy target open. The manifests lived in a private homelab repo, so every server change needed a commit there. A public repo can ship its own manifests if the cluster limits what they may create.

## Decision

- **Location.** The Deployment and Service live in `infra/` in this repo, with a `kustomization.yaml` that pins the image `ghcr.io/a19simma/fleet-server` to tag 0.2.1 as a baseline floor.
- **Allowed kinds.** Deployment, Service, ExternalSecret and Password (the external-secrets generator, added for the master key in ADR-0040), in namespace `fleet-server`. The Argo CD project in the cluster operator's repo allows only those kinds in that namespace. `infra/check-kinds.sh` renders the kustomization in CI and fails on any other kind, on a namespace other than `fleet-server`, on a Service type other than ClusterIP, on a pod that sets `hostNetwork`, `hostPID`, `hostIPC`, `hostPath` or privileged, and on a container or initContainer without requests for cpu, memory and ephemeral-storage or limits for memory and ephemeral-storage. A cpu limit is optional. The homelab quota requires cpu requests and memory and ephemeral-storage limits. A test script proves each rejection.
- **Contract with the operator.** The operator owns the Namespace, the Secret `fleet-server-secrets` (keys `FLEET_DATABASE_URL`, `FLEET_TOKEN`, optional `FLEET_CLIENT_TOKEN`), the Postgres database and role, the GRPCRoute and gateway, the quota and the network policy. The Deployment reads `FLEET_CLIENT_TOKEN` with `optional: true`, so a Secret without it keeps working.
- **Image tag.** Argo CD Image Updater with the `argocd` write-back method overrides the kustomize image tag. It needs no git write access to this repo.
- **Tracking.** The Application tracks `main`.
- **GRPCRoute.** It stays out of this repo because it holds a private hostname and gateway.

## Consequences

- A push to `main` equals deploy rights in the `fleet-server` namespace. A Deployment can read the namespace Secret and the database. Protecting `main` is a hard requirement.
- Pod Security `restricted`, the quota and the network policy sit in the operator's repo, where a change here cannot reach them.
- The pod spec meets `restricted`: non-root, seccomp `RuntimeDefault`, no privilege escalation, all capabilities dropped, read-only root filesystem. It also sets `automountServiceAccountToken: false`.
- The check script catches a bad kind before merge. The Argo CD project is the enforcement at deploy time, and the two lists must agree.
- Unverified: that the Image Updater `argocd` write-back overrides a kustomize `images` entry as described, and that it picks a tag newer than the 0.2.1 baseline without a git commit. Confirm against the Image Updater documentation and a first sync.
- Unverified: the exact Argo CD project fields (`sourceRepos`, `destinations`, `namespaceResourceWhitelist`, an empty `clusterResourceWhitelist`) that express "Deployment, Service, ExternalSecret and Password only". They live in the operator's repo.
- Inferred, not part of the design: `automountServiceAccountToken: false`, the Service type and `hostPath` rules in the check, and the `check-kinds` CI job.
- Inferred, not part of the design: the check reads rendered text with `grep`, so an unusual rendering can slip past it. The Argo CD project is the control that holds.

## Considered and rejected

- **Manifests only in the operator's repo.** Every server change needs a second commit in a private repo.
- **Cluster-wide Argo CD rights for this repo.** A push to `main` could create a Role or a Namespace.
- **GRPCRoute in `infra/`.** It would publish a private hostname.
- **Image tag written back to git.** Needs a git write credential for the cluster.
