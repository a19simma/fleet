# Job docker and build-chain egress

Status: Proposed 2026-11-01. Spike pending: the per-job rootless daemon ships only after a live spike on the box passes. Amends ADR-0031 and ADR-0038.

Integration tests in a Job often need docker. Build chains (cargo, npm, pip) need package hosts. Both collide with the isolation of ADR-0031 and the egress ceiling of ADR-0038. This ADR fixes what a Job may never reach, names the candidate for docker, and states how build egress stays under the ceiling.

## Decision

### Root docker socket is refused

A Job never reaches a root docker socket. Access to that socket equals root on the box: `docker run -v /:/host` bind-mounts the whole filesystem. So:

- `fleet-job` is not in the `docker` group.
- The agent unit makes the socket paths inaccessible (`InaccessiblePaths=`).

### Candidate: per-job rootless dockerd

For integration tests, the candidate is a rootless `dockerd` per Job, in its own unit `fleet-docker@<id>.service`:

- Runs as `fleet-job`.
- `PrivateNetwork=yes`: the namespace has loopback only, so containers have no route out.
- Socket at `/run/fleet/<id>/docker.sock`, reachable by that Job only. Every Job runs as the same `fleet-job` uid, so the file mode cannot keep one Job out of another Job's socket. The separation comes from the per-Job directory binding of `/run/fleet/<id>`, and the spike must show it holds.
- Gated by a Box config key, and refused unless the Job is `disposable=true`.
- Daemon pulls use `HTTPS_PROXY` pointed at the existing agent-exec loopback forwarder (ADR-0031). Every pull passes the CONNECT proxy and stays under the `egress_allow` ceiling (ADR-0038).

Rootless mode needs `newuidmap`, a setuid helper. The unit therefore relaxes `NoNewPrivileges` and `RestrictSUIDSGID`. This is a deliberate relaxation of ADR-0031 for that unit only. The agent unit keeps both settings.

### Spike gate

Nothing in this section is built until a live spike on the box passes. The spike must show: a pull through the proxy, a container with no route out, the socket unreachable from another Job, and the relaxed unit unable to reach the agent unit's state.

### Build-chain egress

Build chains use exact hosts only. `config.rs` rejects wildcard TLDs, and no Profile can add hosts (ADR-0038). The candidate hosts below are unverified until the observe-mode task (BOX-3, the `egress_observe` key) captures real traffic:

| Chain | Candidate hosts |
| --- | --- |
| cargo | `index.crates.io`, `static.crates.io`, `crates.io` |
| npm | `registry.npmjs.org` |
| pip | `pypi.org`, `files.pythonhosted.org` |
| Docker Hub | `registry-1.docker.io`, `auth.docker.io`, `production.cloudflare.docker.com` |
| GitHub | `github.com`, `api.github.com`, `codeload.github.com`, `objects.githubusercontent.com` |

The list stays under the Box `egress_allow` ceiling. The Box owner adds hosts to the ceiling; a Job only narrows it.

### Unverified

- `dockerd` honours `HTTPS_PROXY` for registry pulls.
- `JoinsNamespaceOf=` between the docker unit and the agent unit gives the shared loopback forwarder.
- `fleet-job` has a usable subuid and subgid range.
- The forwarder limits of ADR-0031 (`MAX_FORWARDED` of 4 connections, `FORWARD_IDLE_TIMEOUT` of 120 s) leave room for the parallel layer pulls of one image. Unverified: a pull that opens more connections or stalls past the idle time can fail.
- `JoinsNamespaceOf=` also shares the docker unit's loopback listeners with the agent unit. Inferred, not part of the design: the agent could then reach any port the daemon opens on loopback. Unverified.
- `rootless-extras` is installed on the box.

### Accepted risk

As in ADR-0031: domain fronting through an allowed host. A CONNECT proxy sees the hostname only. The Docker Hub and GitHub rows include shared CDN hosts (`production.cloudflare.docker.com`, `objects.githubusercontent.com`) that serve many tenants, so a fronted request to another tenant on the same host passes the ceiling.

## Options

| Option | Verdict | Reason |
| --- | --- | --- |
| Root docker socket | Refused | Equals root on the box. |
| Shared rootless daemon | Rejected | Images, containers and volumes leak across Jobs. |
| Per-job rootless daemon | Candidate | Isolated per Job, no route out, pulls under the ceiling. Needs the `newuidmap` relaxation. |
| Rootless podman | Rejected | Same `newuidmap` issue, no daemon to proxy through. |
| Sysbox | Rejected | Needs a root runtime. |
| None | Fallback | Jobs run without docker until the spike passes. |

## Consequences

- No Job reaches a root socket on any Box.
- One unit runs with `NoNewPrivileges` and `RestrictSUIDSGID` relaxed, only for disposable Jobs on a Box that enables it.
- Build hosts stay in Box config, so adding a package host is an owner decision.
- If the spike fails, the answer is "none".
