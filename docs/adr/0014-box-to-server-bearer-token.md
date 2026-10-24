# Box to server bearer token

Status: Accepted

fleetd must prove to the Fleet server that it is a Box of this swarm. The server is a hosted service reached over a VPN. The VPN may be Tailscale, netbird or another. The mechanism must work on any routable network path and must not read identity from the VPN.

## Decision

A shared bearer token, for the proof of concept.

- **Wire.** fleetd sends gRPC metadata `authorization: Bearer <token>` on every call to `FleetIngest`, `FleetQuery` and `FleetJobs`. The server compares it in constant time and answers `UNAUTHENTICATED` on a mismatch. The laptop `fleet` CLI sends the same token (decided 2026-10-24). One token covers both write and read for the proof of concept. The services stay separate in the proto so a read credential can be added later without an API change.
- **Storage.** The token is `FLEET_TOKEN` in `/etc/swarm/secrets.env`, mode 0640 `root:agent`, the existing secrets pattern. The laptop-side source file is `~/.config/fleet/token`, mode 600. It is baked into the Template like the other secrets. fleetd already redacts every value in that file from events (ADR-0012), so the token cannot leak through an event.
- **Server address.** `FLEET_SERVER_URL` in `/etc/swarm/box.env`. Plain config, any routable address or name. TLS is optional and set by the deployment. The proto, fleetd and the server read no VPN state.
- **Box identity.** The envelope `box` is the configured box name, sent beside the hostname, the machine-id and the boot id (ADR-0012). The server stores them as claimed. It rejects a `box` that does not match `box-<n>`. A valid token proves membership in the swarm, not which Box.
- **Authorization.** A valid token allows ingest, heartbeat and claim of Jobs addressed to the sending `box`, and also every `FleetQuery` and `FleetJobs` call: any holder can read all Boxes and submit or cancel Jobs. Server-side checks still reject a `box` that does not match `box-<n>` on ingest and claim.
- **Not in scope.** An existing VPN may still carry ssh access to Boxes and Template provisioning. That is separate from fleet traffic. Changing the VPN is a change to `FLEET_SERVER_URL` and a note in this ADR.

## Phase 0 result (T7)

Verified on one Box on 2026-10-24 with a throwaway python grpcio 1.84.1 server on loopback, plain, no TLS. No token and a wrong token give `UNAUTHENTICATED`, and the right token gives OK, from a python client and from grpcurl 1.9.4. The constant-time compare on the full `Bearer <token>` string is enough. The metadata key must be lowercase `authorization`. A 0640 `root:agent` secrets file is readable by `agent` and denied to `nobody`. Redaction removed a token that appeared twice in an event. No result contradicts the decision.

Notes that refine it:

- The interceptor must wrap every service. It also blocks gRPC reflection, so `grpcurl` without a proto needs the token. Behind the interceptor, reflection leaks nothing.
- Redaction matches exact values. It misses base64, URL-encoded and split forms, so "the token cannot leak through an event" holds for literal occurrences only.
- Not run: a tonic client, TLS, and a real VPN path. A Phase 1 pre-check confirms the tonic `MetadataValue` for `Bearer <token>` parses as ASCII with no newline.
- The `FLEET_TOKEN` entry does not exist in `/etc/swarm/secrets.env` yet. T7 used a throwaway file with the same mode and ownership.

## Downsides

- One leaked token exposes the fleet: an attacker with it can inject events, claim Jobs as any `box-<n>`, and read every Box's prompts and transcript summaries. Every Box holds it, so one compromised Box leaks it.
- Rotation means a Template rebuild with re-created Boxes, or a secrets push to each Box.
- No per-Box revocation. A box name is a claim.
- Without TLS the token crosses the VPN in clear text. The deployment decides whether that is acceptable.

## Upgrade path

1. Per-Box tokens minted at first boot, which gives per-Box revocation and trusted box names. This needs an enrollment step that the first-boot unit can authenticate to.
2. mTLS or JWT on top, when the server is exposed beyond a private VPN.

The wire format stays `authorization: Bearer`, so fleetd changes only where it reads the token.

## Decisions (2026-10-24)

- Accepted 2026-10-24.
- Tailscale is not a hard dependency. The token is the only fleet auth.
- Per-Box tokens stay the upgrade path.

## Consequences

- A fourth baked credential beside the existing three: a Claude subscription token, a git credential and a VPN auth key.
- Nothing in fleetd, server, proto or CLI depends on Tailscale, so a VPN switch needs no code change.
- Box names in the database are claims until per-Box tokens exist.
- A token rejected by the server queues events on the Box (ADR-0012). The heartbeat gap shows on the laptop side.

## Considered and rejected

- **VPN identity, such as Tailscale whois and an ACL tag.** Hard-wires the server to Tailscale and to a hosting path that can query a node. Rules out a VPN switch.
- **Per-Box mTLS.** Needs a CA and issuance at first boot, more than a proof of concept justifies.
- **Token minted by the server at first boot.** Needs an unauthenticated enrollment endpoint, the problem it would solve. Kept as the upgrade path once enrollment has its own trust anchor.
