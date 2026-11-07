# The server fetches the release manifest

Status: Proposed 2026-11-07, not built. The operator decided every point below. Amends the relay
description of ADR-0047 only. The trust model of ADR-0047 and ADR-0050 is unchanged. The build is
tasks FEED-2 to FEED-7.

Not built: every item below. Today `UpdateRelay` (`crates/fleet-server/src/service.rs`) reads the
manifest from a file named by `FLEET_UPDATE_MANIFEST` (`crates/fleet-server/src/config.rs`) and
the signature from the same path plus `.minisig`. It relays both verbatim in `HeartbeatReply`. An
operator must copy two files onto the server host after each release, and nobody does it. Boxes
therefore never see an update.

ADR-0047 says the server only relays a signed manifest. This ADR keeps that and adds where the
bytes come from: the server fetches them from GitHub Releases itself.

## Decision

### The feed

- `FLEET_UPDATE_REPO=owner/repo` names the repository. The server derives two URLs:
  `https://github.com/<repo>/releases/latest/download/manifest.json` and the same with
  `.minisig` appended.
- `/releases/latest` skips drafts and prereleases (unverified, to be confirmed against GitHub docs before FEED-4). The release workflow
  (`.github/workflows/release.yml`) uploads `manifest.json` and `manifest.json.minisig` to the
  draft release and publishes it last in `publish-release`, so `latest` never points at a release
  without a signed manifest. The feed is latest-only: there is no prerelease channel.
- No GitHub API call and no token. The two downloads are public.
- There is no free-form URL variable. The operator names a repository and the server owns the URL
  shape, so the variable cannot aim the server at an arbitrary host.
- `owner/repo` is parsed with the grammar of `fleet_core::repo::RepoRef` before it is placed in a
  URL.

### Polling

- `FLEET_UPDATE_POLL_SECS` defaults to 900 and accepts 60 to 86400. Startup refuses a value
  outside the range.
- Each wait is the interval with jitter of plus or minus 10 percent.
- The first poll runs in a spawned task. It never blocks readiness: a server whose first fetch
  hangs still serves.
- One cycle fetches the manifest and then the signature under a 30 second cycle timeout.
- Backoff on failure doubles the wait up to 1 hour. It resets only after an accepted fetch, never
  after a bare 200.
- Each body is read with `take(cap + 1)` against `fleet_proto::MAX_MANIFEST_BYTES` (16 KiB) and
  `fleet_proto::MAX_SIGNATURE_BYTES` (1 KiB). A body over its cap fails the cycle. The manifest
  must parse as JSON, as the file mode checks today.

### The cache

The relay holds the last good pair, the manifest bytes and the signature bytes, in memory.

- A failed fetch never evicts the pair. A box keeps getting the last good pair while GitHub is
  down.
- There is no maximum age on the cached pair. Boxes decide what is acceptable, and the manifest
  `seq` is the freshness rule (ADR-0047). A stale pair only withholds an update, which a server
  could always do.
- The cache is in process only. A restart starts empty and fills on the first accepted fetch.

### The seq gate

The server reads `seq` from the fetched manifest to decide whether to replace the pair. This is a
sanity gate on what the server stores, not a trust decision.

| Fetched `seq` against the cached pair | Action |
| --- | --- |
| first success, nothing cached | store |
| higher | replace |
| equal, same bytes | no-op |
| equal, different bytes | reject, keep the cached pair |
| lower | reject, keep the cached pair |

`seq` is the `GITHUB_RUN_NUMBER` of the release workflow run, so it rises with each release.

### Who verifies

The server never signs and never verifies. fleetd verifies the signature against its trust root,
and checks `seq` and the version policy, exactly as ADR-0047 and ADR-0050 say. A compromised
server, or a compromised GitHub path, can withhold a manifest or replay an old one. It cannot
forge one, and an old one fails fleetd's `seq` check.

### Torn pairs

The manifest and the signature are two fetches at two moments. A release published between them
gives a new manifest with an old signature, or the reverse. The pair then fails verification on
every box, and the box refuses it. The next poll fetches both again and heals the
pair. The server does not retry inside a cycle to close the window.

### Config

- `FLEET_UPDATE_REPO` and `FLEET_UPDATE_MANIFEST` both set is a startup error.
- `FLEET_UPDATE_MANIFEST` stays as break-glass: an operator who must relay a hand-signed manifest
  sets the file and leaves the repository unset. File mode keeps its current behaviour.
- With neither set, the relay sends nothing, as today.

### Transport

The downloads go through the SSRF-safe `PinnedHttps` connector of ADR-0059. GitHub answers a
release download with a redirect to a signed asset URL, and `PinnedHttps` follows no redirect.
ADR-0061 adds the wrapper that follows the redirects.

## Consequences

- An operator sets one variable and releases reach boxes with no copy step.
- The server now makes outbound calls on a timer. The egress is three hosts: `github.com` for the first hop and two asset hosts for redirects (ADR-0061).
- A poll interval of 900 seconds, plus the box heartbeat interval, bounds how long a release
  takes to reach a box.
- A GitHub outage delays new releases and leaves boxes on the last good pair.
- A new server instance relays nothing until its first accepted fetch.
- ADR-0047's sentence "the server relays it in the heartbeat" stays true. What changes is the
  source of the bytes.

## Considered and rejected

- **A free-form manifest URL variable.** It lets a config typo or an injected value point the
  server at any host.
- **The GitHub API.** It needs a token or a rate budget and adds nothing the public download
  lacks.
- **A prerelease channel.** One channel keeps the policy small. A later ADR can add it.
- **A maximum age on the cached pair.** The server cannot tell a quiet repository from a dead
  feed, and `seq` already stops replay on the box.
- **Persisting the cache to disk.** A restart refills it in one poll, and a file adds a path to
  protect.
- **The server verifying the signature.** It would put a trust decision in the component the
  trust model treats as untrusted.
- **Dropping file mode.** The operator wants a break-glass path that needs no GitHub.
