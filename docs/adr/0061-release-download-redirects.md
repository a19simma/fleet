# Redirects for release downloads over the no-redirect transport

Status: Proposed 2026-11-07, partly built (FEED-3, FEED-4, FEED-5). The operator decided every point below. Amends the scope
of the "follows no redirect" rule of ADR-0059. Builds on ADR-0060. The build is tasks FEED-2 to
FEED-7.

Built (FEED-3): the three Request shape items below and the 2048-byte `Location` cap, which
`PinnedHttps` enforces, not the wrapper. Built (FEED-4): `ReleaseFetcher`, the hop rules, the host
allowlist and `Location` parsing. Built (FEED-5): the cache, the seq gate and the poller, in `crates/fleet-server/src/update_feed.rs`. Not built: the relay wiring and startup (FEED-6, FEED-7). `PinnedHttps` (`crates/fleet-server/src/cred/pinned.rs`) resolves a
host once, vets every address, dials the vetted one and returns a 3xx with its body unread and its `Location` captured. ADR-0059 made that
rule for the repository verifier, where a redirect means a renamed repository and an
`Authorization` header must not travel. A release download is different: GitHub answers
`/releases/latest/download/<asset>` with a 302 to `https://github.com/<repo>/releases/download/<tag>/<asset>` on the same host, and
that answers a second 302 to a signed asset URL on `release-assets.githubusercontent.com`, then 200.
Evidence, by kind:

- Live probe, 2026-11-07, against `cli/cli` v2.103.3: 302, then 302, then 200. This is the shape the
  hop rules below are built for.
- Blog quoting a maintainer, second-hand: GitHub Support told StepSecurity it had turned on a feature
  flag adding `release-assets.githubusercontent.com` for release assets. StepSecurity first saw the
  traffic on 2025-04-28 (blog, own observation)
  ([StepSecurity](https://www.stepsecurity.io/blog/harden-runner-detects-new-traffic-to-release-assets-githubusercontent-com-across-multiple-customers)).
- Still unverified: what `objects.githubusercontent.com` serves today. It stays on the list for older
  artifacts.

ADR-0060 needs the server to follow the chain.

## Decision

### Scope of the amendment

ADR-0059's rule stays for the repository verifier and for every call that carries credentials.
`PinnedHttps` itself stays no-redirect. A new `ReleaseFetcher` wrapper sits outside it, calls it
once per hop and decides whether to follow. Only the release feed uses `ReleaseFetcher`.

### Request shape

- `ForgeGet.authorization` becomes an `Option`. The release feed sends no `Authorization` header
  on any hop.
- `Accept` becomes a field of `ForgeGet`, so the feed can ask for `application/octet-stream`.
- `ForgeReply` gains a `location` field, set on a 3xx only. The body of a 3xx is still never
  read.

### Hop rules

- Followed statuses: 301, 302, 303, 307 and 308. Every hop is a `GET`.
- At most `MAX_RELEASE_HOPS` redirects, 3. A fourth is a failure.
- A URL visited earlier in the chain is refused, so a loop ends at once.
- Every hop is resolved again and vetted again with `allow_private` false. No address carries
  over from an earlier hop.
- The final status must be 200. Any other final status fails the fetch.
- The body is capped at the proto cap of the asset (ADR-0060). The whole cycle fits the 30 second
  cycle timeout of ADR-0060.

### Host allowlist

A constant lists the hosts a release download may touch:

| Hop | Hosts |
| --- | --- |
| first | `github.com` |
| redirect | `github.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com` |

A redirect hop may name `github.com` because the `latest/download` URL redirects to
`releases/download/<tag>` on the same host. The match is exact. The visited-URL check and
`MAX_RELEASE_HOPS` still bound the chain, so a `github.com` self-loop ends in a loop refusal.

Both sides read one source of truth: `UPDATE_FIRST_HOP_HOST` and `UPDATE_REDIRECT_HOSTS` in
`fleet-proto`. The server's `FIRST_HOP_HOST` and `REDIRECT_HOSTS` are those constants, and fleetd's
`DEFAULT_UPDATE_HOSTS` (`crates/fleetd/src/config.rs`) is built from them. A fleetd test pins
`DEFAULT_UPDATE_HOSTS` equal to the first-hop host plus the redirect hosts, and a server test pins
the server constants to the shared ones. fleetd
accepts the three hosts on every hop. The server takes `github.com` as the first-hop host, and a
redirect may name the first-hop host or a redirect host. A server test pins the accepted redirect set
to exactly that union.

### The Location header

The `Location` value is untrusted input. It is capped at 2048 bytes and parsed with a real URL
parser. The wrapper refuses a value with any of these:

| Hostile form | Reason |
| --- | --- |
| scheme other than `https` | no plaintext hop |
| userinfo, as in `https://github.com@evil.example/` | host confusion |
| port other than 443 | the transport dials 443 only |
| IP literal, v4 or v6 | host allowlist matches names |
| trailing dot in the host | a second spelling of an allowlisted name |
| host not on the allowlist for that hop | off-list hop |
| non-ASCII host | punycode and homoglyph confusion |
| fragment, in a `Location` or in the first-hop path | never sent, so a sign of a hand-built value |
| control character or whitespace, including CR and LF | header injection |
| relative reference or protocol-relative `//host/path` | the allowlist cannot judge it |

The host is lowercased and matched as an exact string before any DNS lookup. Each row of the table
gets one test.

### Redaction

Logs carry the hop count, the status and the host. They never carry the query string of a signed
asset URL.

## Consequences

- The release feed can follow GitHub's asset redirect without widening the credential path: no
  header travels, and no hop leaves the three hosts.
- A GitHub change to a new asset host is one edit in `fleet-proto`. The pin tests fail if either
  side stops reading the shared constants.
- `ForgeGet` and `ForgeReply` change shape, so the repository verifier and its fakes need updating
  with no change in behaviour.
- The repository verifier still treats a 3xx as an error. A renamed repository still gives
  `UPSTREAM_UNAVAILABLE`.

## Considered and rejected

- **Teach `PinnedHttps` to follow redirects.** Every caller would inherit it, including the ones
  that carry a credential.
- **An allowlist suffix match on `githubusercontent.com`.** User-controlled subdomains of that
  zone exist. Exact names only.
- **Follow redirects with a credential.** The feed is public, so no header is needed and none is
  sent.
