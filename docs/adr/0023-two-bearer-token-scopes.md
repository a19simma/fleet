# Two bearer token scopes

Status: Accepted. Built: the server checks the box token and the client token by service path. Amends ADR-0014.

ADR-0014 uses one shared token for ingest, claim, query and Job control, and says the services stay separate so a read credential can be added later. The laptop CLI now submits and cancels Jobs and reads transcripts, so it needs its own credential.

## Decision

The server holds two static bearer tokens, each with a scope.

- **Box token.** `FLEET_TOKEN`, in `/etc/swarm/secrets.env` as before. Scope: `FleetIngest` and `FleetWorker`.
- **Client token.** `FLEET_CLIENT_TOKEN`, in server config. Scope: `FleetQuery` and `FleetJobs`. The CLI reads it from the environment or `~/.config/fleet/token`, beside `FLEET_SERVER_URL`.
- **Interceptor.** It maps the token to a scope and checks the gRPC path. A bad or missing token gets `UNAUTHENTICATED`. A valid token on a path outside its scope gets `PERMISSION_DENIED`. The compare stays constant time.
- **Box names.** `ClaimJob` and `ReportJob` keep the `box-<n>` check. A box name is still a claim.
- **TLS.** The CLI client needs the tonic rustls feature for https through a gateway.
- **Wire format.** Unchanged: `authorization: Bearer <token>`.

## Consequences

- A leaked Box token can inject events and claim or report Jobs as any `box-<n>`. It can no longer read transcripts or submit Jobs.
- A leaked client token can read all Box data and submit or cancel Jobs. It cannot inject events or claim Jobs.
- Every Box still holds the same token, so one compromised Box leaks it. Per-Box revocation does not exist.
- Inferred, not part of the design: rotating either token is a config change plus a restart, and for the Box token a secrets push or Template rebuild.
- The per-Box token upgrade path in ADR-0014 stays open and needs only a change in where fleetd reads the token.

## Considered and rejected

- **Keep one token.** A leaked Box token would read prompts and submit Jobs.
- **A token per Box.** Gives revocation, but needs an enrollment step with its own trust anchor. Kept as the upgrade path.
- **VPN identity.** Hard-wires the server to one VPN (ADR-0014).
