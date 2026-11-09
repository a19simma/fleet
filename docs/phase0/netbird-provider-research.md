# NetBird provider research (ENV-8a)

Research only. No code, no host touched. Versions: NetBird v0.82.0 (source tag), systemd man pages 262 and source tag v257. Source kinds are labelled on every link: source code, official docs, maintainer, blog. Anything not confirmed in a primary source is marked unverified. Lines marked "Inferred" are this report's reasoning, not a sourced fact.

## 1. Spike pass criteria (written first, used by ENV-8b)

The spike passes only if every row below is shown by probe output on a live Box. Any miss is a no-go record.

| # | Criterion | Probe output that proves it |
|---|---|---|
| P1 | The peer appears when the Job starts and disappears with the Job. | Management peer list shows one peer named for the Job while it runs. After the Job ends, the peer is gone within the ephemeral window, or the teardown path deletes it at once. Record both times. |
| P2 | The Setup unit reaches a private host through the tunnel and not the public internet. | A request to a private address succeeds from the Setup unit. The same request with the tunnel stopped fails. A packet capture or the proxy log shows no direct path. |
| P3 | The agent unit cannot reach the tunnel. | From the agent unit, a connect to the tunnel entry point (proxy port, socket, or namespace) fails. The same connect from the Setup unit succeeds as a positive control. |
| P4 | The setup key never reaches an argv, a log or the agent. | `ps` argv of every process holds no key. The key string is absent from the journal, fleetd logs and the transcript. The agent unit cannot read the key file or the process environment holding it. Positive control: the scan finds a planted marker string in a known place. |
| P5 | The tunnel does not widen policy unseen. | The Box config gate `providers = ["netbird"]` is off by default and no Profile or Environment can set it. With it off, no netbird process starts. |
| P6 | Reach is limited to the named host. | The ephemeral peer's group can reach one `/32` resource and nothing else on the NetBird network. |

## 2. Findings

### 2.1 Netstack (userspace) mode

- Enabled by environment variable only. `NB_USE_NETSTACK_MODE` must be the exact string `true`. No `--netstack` flag exists in v0.82.0 (searched `client/cmd/root.go`). Run with `netbird up -F`. [source code: env.go](https://github.com/netbirdio/netbird/blob/v0.82.0/client/iface/netstack/env.go), [official docs: environment variables](https://docs.netbird.io/client/environment-variables).
- In this mode a local SOCKS5 proxy binds TCP `127.0.0.1:1080` by default, with no authentication. Override variables: `NB_SOCKS5_LISTENER_PORT`, `NB_SOCKS5_LISTENER_ADDRESS`. The source comment:
  > The proxy is a bridge for local host applications into the userspace WireGuard netstack, so it binds to loopback by default. Override this only when the proxy must be reachable from other hosts (e.g. a container gateway); doing so exposes an unauthenticated SOCKS5 proxy on that address.

  [source code: env.go](https://github.com/netbirdio/netbird/blob/v0.82.0/client/iface/netstack/env.go). The listener is a plain TCP listen, so there is no unix socket option. [source code: proxy.go](https://github.com/netbirdio/netbird/blob/v0.82.0/client/iface/netstack/proxy.go).
- Any process in the same network namespace can use that proxy and reach whatever the peer's policy allows. Inferred from loopback TCP with no auth; no per-process isolation exists.
- Limits: DNS is not supported in this mode (IP addresses only) and outbound goes through SOCKS only. [official docs: FaaS](https://docs.netbird.io/use-cases/cloud/netbird-on-faas), [official docs: Docker](https://docs.netbird.io/get-started/install/docker).
- No root and no `NET_ADMIN` are needed in this mode per the FaaS docs. Partly unverified in source: the embed package comment reads "NoUserspace disables the userspace networking mode. Needs admin/root privileges" ([source code: embed.go](https://github.com/netbirdio/netbird/blob/v0.82.0/client/embed/embed.go)), which says the kernel mode needs root and agrees with the docs.
- Embed Go package (`client/embed`). Options include `SetupKey`, `ManagementURL`, `ConfigPath`, `StatePath`, `NoUserspace`. Methods include `Dial`, `ListenTCP`, `NewHTTPClient`. It sets netstack mode and skips the SOCKS listener, so traffic stays in-process. An empty `ConfigPath` keeps config in memory. It needs exactly one of `SetupKey`, `JWTToken`, `PrivateKey`. [source code: embed.go](https://github.com/netbirdio/netbird/blob/v0.82.0/client/embed/embed.go), [official docs: pkg.go.dev](https://pkg.go.dev/github.com/netbirdio/netbird/client/embed). Inferred: embed is the narrowest option (no daemon, no IPC socket, no proxy port, no disk writes). It means a small Go helper that fleetd owns or ships.
- Daemon IPC is a separate unix socket (upstream unit: a path under the runtime directory). Since v0.76 the daemon checks callers and treats the same uid as privileged. [source code: netbird@.service](https://github.com/netbirdio/netbird/blob/v0.82.0/release_files/systemd/netbird@.service), [blog: v0.76 IPC security](https://netbird.io/knowledge-hub/netbird-v0-76-daemon-ipc-security) (vendor blog, summary only, advisory not read). Unverified in source.
- One user report that netstack mode connected and pinged but inbound access did not work without `NB_ENABLE_NETSTACK_LOCAL_FORWARDING`. [maintainer-hosted, user report: issue 2799](https://github.com/netbirdio/netbird/issues/2799). Lead only.

### 2.2 Ephemeral peers

- Ephemeral is a property of the setup key. Registration copies it to the peer: `config.Ephemeral = sk.Ephemeral`. [source code: peer.go](https://github.com/netbirdio/netbird/blob/v0.82.0/management/server/peer.go). The dashboard and the Terraform `netbird_setup_key` resource both expose it. [official docs: setup keys](https://docs.netbird.io/manage/peers/register-machines-using-setup-keys), [official docs: Terraform](https://registry.terraform.io/providers/netbirdio/netbird/latest/docs/resources/setup_key).
- Deletion window: `EphemeralLifeTime = 10 * time.Minute`, plus a one minute cleanup window, so up to about 11 minutes after disconnect. A reconnect before the deadline cancels deletion. [source code: interface.go](https://github.com/netbirdio/netbird/blob/v0.82.0/management/internals/modules/peers/ephemeral/interface.go), [source code: ephemeral.go](https://github.com/netbirdio/netbird/blob/v0.82.0/management/internals/modules/peers/ephemeral/manager/ephemeral.go). The value is a compile-time constant. Unverified: any per-account or self-hosted override.
- Consequence for P1: "disappears with the Job" is true only within about 11 minutes by default. For an immediate removal the teardown must call the management API delete for that peer. That needs an API token, a second secret (see 2.4).

### 2.3 Setup keys and custody

- One-off keys register one machine, reusable keys a set count. Expiry defaults to 7 days in the UI. Auto-groups place the peer in groups on registration. [official docs: setup keys](https://docs.netbird.io/manage/peers/register-machines-using-setup-keys).
- Delivery without argv: `--setup-key-file` with `NB_SETUP_KEY_FILE` (file read and trimmed), or `NB_SETUP_KEY`. The inline value wins over the file. No stdin option found. [source code: root.go](https://github.com/netbirdio/netbird/blob/v0.82.0/client/cmd/root.go). Inferred: an environment value shows in the process environment to the same uid and root, so a mode 0600 file read by the Setup-side helper is the cleaner path. The Environment secret delivery design (files in a tmpfs, ADR-0067 direction) already fits this.
- Client persistence: the profile config struct has no setup key field and the key is used only in the register request. [source code: config.go](https://github.com/netbirdio/netbird/blob/v0.82.0/client/internal/profilemanager/config.go), [source code: auth.go](https://github.com/netbirdio/netbird/blob/v0.82.0/client/internal/auth/auth.go). Foreground mode writes the WireGuard private key and config to disk. [source code: login.go](https://github.com/netbirdio/netbird/blob/v0.82.0/client/cmd/login.go). Unverified: whether any debug or trace log line prints the key. Not audited.
- After registration the key stays valid server side. Revoking or expiry does not disconnect registered peers:
  > When you revoke a key, all machines already authenticated with it remain connected to the network. The same applies when the key expires.

  [official docs: setup keys](https://docs.netbird.io/manage/peers/register-machines-using-setup-keys) (near-verbatim, via a summarising fetch).
- Custody recommendation (Inferred): a one-off, ephemeral, short-expiry key minted per Job by the server or an operator job, so a leak is one dead key. The alternative is a reusable operator key held in the Box secrets file, which is a standing credential on the Box. Who mints per-Job keys needs an API token held by the server, which is a new trust edge (open question 1).

### 2.4 Restricting the peer to one private host

- Without policies traffic is denied. The built-in `Default` policy allows all peers, and every peer joins the `All` group at registration. So the Default policy must be removed or narrowed, or the ephemeral peer reaches everything. [official docs: access control](https://docs.netbird.io/manage/access-control/manage-network-access), [source code: peer.go, `AddPeerToAllGroup`](https://github.com/netbirdio/netbird/blob/v0.82.0/management/server/peer.go).
- Recipe from the docs: ephemeral key with an auto-group, a `/32` network resource behind a routing peer, a one-way policy from that group to the resource. The docs advise single-host `/32` resources over broad ranges. [official docs: networks](https://docs.netbird.io/manage/networks). Unverified: full isolation of an `All`-only peer on v0.82.0 (untested) and per-port rules on resources.

### 2.5 systemd: JoinsNamespaceOf with PrivateNetwork

- Semantics:
  > If a unit that has this setting set is started, its processes will see the same `/tmp/`, `/var/tmp/`, IPC namespace and network namespace as one listed unit that is started. If multiple listed units are already started and these do not share their namespace, then it is not defined which namespace is joined. Note that this setting only has an effect if `PrivateNetwork=`/`NetworkNamespacePath=`, `PrivateIPC=`/`IPCNamespacePath=` and/or `PrivateTmp=` is enabled for both the unit that joins the namespace and the unit whose namespace is joined.

  [official docs: systemd.unit(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html). The inverse dependency is implied, so declaring it on one unit joins both. Introduced in v209 per the docs' version note (not confirmed against NEWS, unverified).
- `PrivateNetwork=yes` configures only `lo`:
  > If true, sets up a new network namespace for the executed processes and configures only the loopback network device `lo` inside it. No other network devices will be available to the executed process.

  [source code: systemd.exec.xml v257](https://github.com/systemd/systemd/blob/v257/man/systemd.exec.xml). Filesystem unix sockets stay reachable, abstract ones of the host do not, and netlink is cut off (same file).
- Ownership and order: the namespace lives in a refcounted shared runtime object. "Whatever process runs this first shall create a new namespace, all others should just join it." [source code: namespace.c, setup_shareable_ns](https://github.com/systemd/systemd/blob/v257/src/core/namespace.c). No ordering is added by the directive, so the unit files need explicit `After=` and `Requires=`. [source code: unit.c](https://github.com/systemd/systemd/blob/v257/src/core/unit.c). Behaviour when the first unit stops while others still run is unverified (the unref path was not read).
- A unit with its own `PrivateNetwork=yes` and no `JoinsNamespaceOf=` gets a fresh namespace and cannot see the other loopback. Inferred from the shared runtime being keyed by unit; not tested. `NetworkNamespacePath=` is ignored when a listed unit already holds a namespace. [source code: systemd.exec.xml v257](https://github.com/systemd/systemd/blob/v257/man/systemd.exec.xml).
- Pitfalls: `DynamicUser=` implies `PrivateTmp=disconnected`, which cannot be joined, so set `PrivateTmp=true` on both units. Without `CAP_NET_ADMIN` (user managers) `PrivateNetwork=yes` is dropped with a notice, so the sandbox would silently fail open. [source code: exec-invoke.c](https://github.com/systemd/systemd/blob/v257/src/core/exec-invoke.c). Both are also marked unverified by the researcher for exact behaviour on the target systemd version.

### 2.6 The combination does not fit as the plan assumes

Inferred, not part of the design: the plan pairs a netbird unit with the Setup unit through `JoinsNamespaceOf` and `PrivateNetwork`. Two facts collide.

1. A shared private namespace holds only loopback. A netbird client inside it cannot reach the management server, relays or peers, since no interface leaves the namespace. Giving it one needs a veth pair or similar wiring that systemd does not provide.
2. A netbird client in the host namespace puts its SOCKS5 listener on host loopback, TCP only. Any unit that shares the host network namespace can use it, including the agent unit if the agent unit is not under `PrivateNetwork=yes`.

So the join cannot carry the tunnel and also keep the agent out. Three shapes remain, ranked:

- A. Embed helper (Go, `client/embed`), run as its own unit in the host namespace with no SOCKS listener. It exposes one filesystem unix socket in a runtime directory with mode and group set so only the Setup unit's user can open it. The agent unit has `PrivateNetwork=yes` plus no access to that directory. Narrowest. Costs a helper binary to maintain.
- B. Stock netbird in netstack mode in the host namespace with SOCKS on a loopback port, and the agent unit under `PrivateNetwork=yes` plus the existing Egress proxy path. P3 then depends on the agent unit never sharing the host namespace, which contradicts any design where the agent reaches the Egress proxy over host loopback. Unverified how ADR-0038 wires that path; check before choosing B.
- C. Kernel mode in a named namespace with `NetworkNamespacePath=`. Needs root and `NET_ADMIN` on the Box and host-side namespace management. Widest. Not recommended.

## 3. Recommendation

Do not write ADR 0068 yet. Run ENV-8b only after the human accepts the policy cost in open question 2 and picks A or B. If the Box already supports a Setup-phase private allow (D2 option B in `.ralph/env-plan.md`), netbird may be unnecessary and ENV-8 can be dropped.

If the spike proceeds, use shape A, a one-off ephemeral key per Job delivered as a tmpfs file, a deny-by-default policy with one `/32` resource, and teardown that deletes the peer through the API on every end path. The ephemeral timer is only the fallback.

## 4. Open questions

1. Who mints per-Job setup keys and deletes peers: the server, fleetd or an operator? Each needs a NetBird API token, a second secret with its own custody.
2. Is a VPN path accepted at all, given it bypasses `egress_allow` and the Egress proxy address checks (ADR-0038)? The Box gate `providers = ["netbird"]` must be settable only by the operator.
3. Is a Go helper (shape A) acceptable in the build, or must the provider be stock binaries?
4. Does the agent unit share the host network namespace today? This decides whether shape B can satisfy P3.
5. Is the roughly 11 minute ephemeral window acceptable as a fallback if API delete fails?
6. Does any netbird log level print the setup key? Not audited. P4 must grep a debug-level run.
7. Is `JoinsNamespaceOf` still wanted for the tmpfs-only share between Setup and the helper? It adds the PrivateTmp pitfalls above for no tunnel benefit.

## 5. Unverified items

- Any netbird log line containing the setup key.
- Per-account override of the 10 minute ephemeral lifetime.
- Whether an `All`-only peer is isolated on v0.82.0 and whether per-port rules exist.
- Unprivileged netbird daemon under `NoNewPrivileges` and an empty capability bound.
- The daemon `--service-env` flag (reported by a search summary, not seen in source).
- systemd: namespace lifetime when the first unit stops, the v209 introduction, abstract socket isolation wording, and cross-namespace reachability for an unprivileged user (kernel semantics expected, no primary source read).
- Docs quotes from docs.netbird.io came through a summarising fetch and are near-verbatim.

## 6. Read more

- netbird: [source code: client/iface/netstack/env.go](https://github.com/netbirdio/netbird/blob/v0.82.0/client/iface/netstack/env.go)
- systemd: [source code: setup_shareable_ns in namespace.c](https://github.com/systemd/systemd/blob/v257/src/core/namespace.c)
