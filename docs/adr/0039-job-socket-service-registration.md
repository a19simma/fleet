# Job socket service registration

Status: Proposed 2026-10-28. `PerJob<S>` is built in `jobsock.rs`. The runner registers the `fetch` feed and the `egress proxy` under the systemd launcher (ADR-0038). No runtime path registers the broker yet (ADR-0037). Clarifies the static `Services` map assumption in ADR-0036, ADR-0037 and ADR-0038, which each say a service is "registered" without saying where or when. Refers to ADR-0036 for the per-job unix socket, ADR-0037 for the credential broker and ADR-0038 for the fetch service.

ADR-0036 binds one socket per Job and hands it a `Services` map, a fixed map from handshake name to `Arc<dyn Service>`. The credential broker (ADR-0037) and the fetch service (ADR-0038) both hold per-Job state: a push target, a fetch cap, a recorded intent. A single instance cannot be built before the Job exists, and a map built once cannot grow when a Job starts. Nothing in the three ADRs says who adds an entry or removes it.

## Decision

### Two kinds of service

- A daemon-wide service holds no per-Job state. One `Arc` goes into the `Services` map of every socket, and the daemon builds it once at start.
- A per-Job service is wrapped in `PerJob<S>`. The wrapper is the one `Arc<dyn Service>` in the map. It looks up `ctx.job_id`, which the listener sets and the client never supplies, and delegates to the service registered for that id.

### Registry

- `PerJob<S>` is a cloneable handle on one shared map from Job id to `Arc<S>`. The runner keeps a clone.
- `register(job_id, service)` fails with `Duplicate` when the id is live and with `InvalidId` when the id is not a valid Job id. It never replaces: a double registration is a bug and must show.
- `unregister(job_id)` is idempotent and reports whether it removed an entry.
- A lookup of an unknown id closes the connection with no reply, the same as an unknown handshake name. No error text names the cause, so a client learns nothing about which ids exist.
- The lock covers one map operation and is never held across an await. Every method recovers a poisoned guard, because a single insert or remove leaves the map whole.

### Lifecycle

- Register before launch. The runner registers the Job's service before it starts the Agent unit, so the first connection finds it.
- Unregister on every end path, through a job end hook: one call site that runs on success, failure, cancel, lease loss, timeout and runner panic. Unregister runs before the Job socket drops.
- Unregister takes effect on the next connection. A connection already served keeps its `Arc` and finishes, or ends when the socket fires the cancel signal in `JobContext`. The socket drop cancels it.
- Direct mode (no systemd launcher, no Job socket) registers nothing. There is no socket to reach it, and the registry stays empty.

## Consequences

- The broker and fetch service can hold per-Job state and be freed when the Job ends, with no global map of their own.
- A missed unregister leaks one `Arc` until the daemon restarts. The job end hook is the guard, and a test of the runner must show each end path calls it.
- A service is not reachable from a Job socket whose id differs from its own, even if the cgroup check were bypassed.
- Wiring the runner is a separate task. The fetch service is reachable under the systemd launcher. The broker stays unreachable at runtime until a runtime path registers it.

## Alternatives

- Rebuild the `Services` map per Job. This works for one socket but spreads the construction across the runner and gives the daemon-wide services a second owner. The registry keeps one map shape.
- Let `register` replace an existing entry. A silent swap hides a double launch of one Job id. An error is cheaper to find.
- Key services on a client-supplied id. The agent is untrusted, so the id would be forgeable. The listener's id is the only key.
- Reply with an error for an unknown id. It tells a probe which ids exist and adds a path to test.
