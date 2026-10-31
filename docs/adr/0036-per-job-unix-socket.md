# Per-job unix socket

Status: Proposed 2026-10-28. The socket is built in `jobsock.rs` and wired for `fetch` and `egress proxy` under the systemd launcher (ADR-0038, ADR-0039). The `broker` service is built as library code and no runtime path registers it (ADR-0037). Mount isolation is unverified. Amends ADR-0031 (P2 proxy socket).

ADR-0037 (credential broker), the fetch tool and the P2 egress proxy each need a channel from the agent to fleetd that carries the identity of one Job. ADR-0031 P2 plans one global `/run/fleet/proxy.sock`, which cannot tell Jobs apart. All agent Jobs share one uid (`fleet-job`), so the peer uid identifies no Job.

## Decision

### Socket and handshake

- fleetd creates one unix socket per Job under `/run/fleet/<job id>/` before it spawns the Agent unit, and unlinks it before it removes the Run dir.
- A client sends one handshake line that selects a service: `broker`, `fetch` or `egress proxy`. Unknown names close the connection with no reply.
- The selected service receives a job context (job id, cancel token) and the stream. A service never reads the job id from the client.
- Frame size and concurrent connections per Job are capped. Both caps are constants shared by the server and the client code (one source, no copies).

### Peer identity

- The check is the cgroup of the peer pid, read from `/proc/<pid>/cgroup`. It must equal `fleet-agent@<job id>.service`.
- fleetd prefers `SO_PEERPIDFD` (kernel 6.5 or later) over a bare pid, because a pid can be recycled between accept and read. Unverified: that tokio or rustix exposes `SO_PEERPIDFD` on the accepted stream. Unverified: the kernel version of the target Boxes.
- A mismatch or an unreadable cgroup closes the connection with no reply and bumps a counter. The log line is fixed and carries no client value.

### Second layer

The unit mounts only its own Run dir: `TemporaryFileSystem=/run/fleet:ro`, `BindPaths=/run/fleet/%i` and the hook dir. Other Jobs' sockets are then absent from the agent's mount namespace. Unverified: this needs a live probe on a Box, including that `BindPaths` after `TemporaryFileSystem` keeps the socket connectable.

### Launcher scope

The socket exists only for `agent_launcher = "systemd"`. In `direct` mode the agent shares fleetd's uid and reads fleetd's environment through `/proc`, so peer checks add nothing. fleetd refuses to create the socket there and logs one fixed line.

## Consequences

- One transport and one identity check serve the broker, fetch and the egress proxy. Each service sees a Job, never a client-chosen id.
- ADR-0031 P2 changes: the global `/run/fleet/proxy.sock` becomes the `egress proxy` service on this socket. The `CONNECT` allowlist and the namespace plan stay as written there.
- A fleetd restart ends every socket. The Job is LOST under the existing restart rules.
- Cancel and lease loss close the job context, so a service stops mid-request.

## Considered and rejected

- **One global socket with a job id in the request.** The agent could name any Job.
- **Peer uid per Job (a uid pool).** Needs a uid allocator and ownership across restarts (see the `DynamicUser=` rejection in ADR-0031).
- **TCP on loopback with a token.** The token sits in the agent's environment, the thing the broker removes.
