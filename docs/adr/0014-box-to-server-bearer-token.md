# Box to server bearer token

Status: Accepted, amended 2026-10-24: two scoped tokens

Amended 2026-10-24: one token became two, a box token and a client token, each scoped by service. The current decision is below. The original single-token decision is kept under "Original decision (2026-10-24)" at the end. See also plan.md Authorization.

fleetd must prove to the Fleet server that it is a Box of this swarm. The server is a hosted service reached over a VPN. The VPN may be Tailscale, netbird or another. The mechanism must work on any routable network path and must not read identity from the VPN.

## Decision

Two shared bearer tokens, scoped by service, for the proof of concept.

- **Scopes.** The box token `FLEET_TOKEN` covers `FleetIngest` and `FleetWorker`. The client token `FLEET_CLIENT_TOKEN` covers `FleetQuery` and `FleetJobs`. A valid token on a service outside its scope, or on an unknown path, gets `PERMISSION_DENIED`. A missing or unknown token gets `UNAUTHENTICATED`. The two tokens must differ.
- **Wire.** fleetd sends gRPC metadata `authorization: Bearer <box token>` on every call to `FleetIngest` and `FleetWorker`. The laptop `fleet` CLI sends `authorization: Bearer <client token>` on every call to `FleetQuery` and `FleetJobs`. The server compares in constant time on the full `Bearer <token>` string. The services stay separate in the proto, which is the seam that makes the split possible.
- **Storage.** The box token is `FLEET_TOKEN` in `/etc/swarm/secrets.env`, mode 0640 `root:agent`, the existing secrets pattern, baked into the Template like the other secrets. fleetd already redacts every value in that file from events (ADR-0012), so the box token cannot leak through an event. On the server, both tokens are env vars: `FLEET_TOKEN` (box) and `FLEET_CLIENT_TOKEN` (client). On the laptop, the CLI reads the client token from `~/.config/fleet/token`, mode 600, or from `FLEET_CLIENT_TOKEN`. Boxes hold only the box token, and the client token is never baked into a Box. Without `FLEET_CLIENT_TOKEN` on the server (unset or empty), `FleetQuery` and `FleetJobs` are closed.
- **Server address.** `FLEET_SERVER_URL` in `/etc/swarm/box.env`. Plain config, any routable address or name. TLS is optional and set by the deployment. The proto, fleetd and the server read no VPN state.
- **Box identity.** The envelope `box` is the configured box name, sent beside the hostname, the machine-id and the boot id (ADR-0012). The server stores them as claimed. It rejects a `box` that does not match `box-<n>`. A valid box token proves membership in the swarm, not which Box.
- **Authorization.** The box token allows ingest, heartbeat and claim and report of Jobs, for the sending `box`. It allows no read of the fleet and no Job submission. The client token allows every `FleetQuery` and `FleetJobs` call: read all Boxes, submit and cancel Jobs, read transcripts. It allows no ingest and no claim. A leaked box token cannot read the fleet or submit Jobs. A leaked client token can read and submit but cannot ingest or claim. Server-side checks still reject a `box` that does not match `box-<n>` on ingest and claim.
- **Not in scope.** An existing VPN may still carry ssh access to Boxes and Template provisioning. That is separate from fleet traffic. Changing the VPN is a change to `FLEET_SERVER_URL` and a note in this ADR.

## Phase 0 result (T7)

Verified on one Box on 2026-10-24 with a throwaway python grpcio 1.84.1 server on loopback, plain, no TLS. No token and a wrong token give `UNAUTHENTICATED`, and the right token gives OK, from a python client and from grpcurl 1.9.4. The constant-time compare on the full `Bearer <token>` string is enough. The metadata key must be lowercase `authorization`. A 0640 `root:agent` secrets file is readable by `agent` and denied to `nobody`. Redaction removed a token that appeared twice in an event. No result contradicts the decision.

Notes that refine it:

- One tower layer wraps the whole router, so it covers every service and every path. It also blocks gRPC reflection, so `grpcurl` without a proto needs the token. Behind the layer, reflection leaks nothing.
- Redaction matches exact values. It misses base64, URL-encoded and split forms, so "the token cannot leak through an event" holds for literal occurrences only.
- Not run: a tonic client, TLS, and a real VPN path. A Phase 1 pre-check confirms the tonic `MetadataValue` for `Bearer <token>` parses as ASCII with no newline.
- The `FLEET_TOKEN` entry does not exist in `/etc/swarm/secrets.env` yet. T7 used a throwaway file with the same mode and ownership.

## Downsides

- A leaked box token lets an attacker inject events and claim and report Jobs as any `box-<n>`. Every Box holds it, so one compromised Box leaks it. It cannot read the fleet or submit Jobs.
- A leaked client token lets an attacker read every Box's prompts and transcript summaries and submit or cancel Jobs. It cannot ingest or claim. It lives on the laptop and the server, not on Boxes.
- Rotation of the box token means a Template rebuild with re-created Boxes, or a secrets push to each Box. The client token rotates on the laptop and the server only.
- No per-Box revocation. A box name is a claim.
- Without TLS the tokens cross the VPN in clear text. The deployment decides whether that is acceptable.

## Upgrade path

1. Per-Box tokens minted at first boot, which gives per-Box revocation and trusted box names. This needs an enrollment step that the first-boot unit can authenticate to.
2. mTLS or JWT on top, when the server is exposed beyond a private VPN.

The wire format stays `authorization: Bearer`, so fleetd changes only where it reads the token.

## Decisions (2026-10-24)

- Accepted 2026-10-24.
- Tailscale is not a hard dependency. The bearer tokens are the only fleet auth.
- Per-Box tokens stay the upgrade path.
- Amended 2026-10-24: two scoped tokens replace the single token.

## Consequences

- A fourth baked credential beside the existing three: the box token, beside a Claude subscription token, a git credential and a VPN auth key. The client token is not baked into Boxes.
- Nothing in fleetd, server, proto or CLI depends on Tailscale, so a VPN switch needs no code change.
- Box names in the database are claims until per-Box tokens exist.
- A token rejected by the server queues events on the Box (ADR-0012). The heartbeat gap shows on the laptop side.

## Considered and rejected

- **VPN identity, such as Tailscale whois and an ACL tag.** Hard-wires the server to Tailscale and to a hosting path that can query a node. Rules out a VPN switch.
- **Per-Box mTLS.** Needs a CA and issuance at first boot, more than a proof of concept justifies.
- **Token minted by the server at first boot.** Needs an unauthenticated enrollment endpoint, the problem it would solve. Kept as the upgrade path once enrollment has its own trust anchor.

## Original decision (2026-10-24)

Superseded by the two scoped tokens above. Kept for the record.

A shared bearer token, for the proof of concept.

- **Wire.** fleetd sends gRPC metadata `authorization: Bearer <token>` on every call to `FleetIngest`, `FleetQuery` and `FleetJobs`. The server compares it in constant time and answers `UNAUTHENTICATED` on a mismatch. The laptop `fleet` CLI sends the same token (decided 2026-10-24). One token covers both write and read for the proof of concept. The services stay separate in the proto so a read credential can be added later without an API change.
- **Authorization.** A valid token allows ingest, heartbeat and claim of Jobs addressed to the sending `box`, and also every `FleetQuery` and `FleetJobs` call: any holder can read all Boxes and submit or cancel Jobs.
- **Downside.** One leaked token exposes the fleet: an attacker with it can inject events, claim Jobs as any `box-<n>`, and read every Box's prompts and transcript summaries.
- **Only fleet auth.** Tailscale is not a hard dependency. The token is the only fleet auth.
