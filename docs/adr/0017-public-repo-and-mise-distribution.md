# Public repo and mise distribution

Status: Accepted

The fleet repo holds fleetd, the Fleet server and the `fleet` CLI. It is public on GitHub at github.com/a19simma/fleet with releases, and Boxes install the binaries through mise. The Template bakes software at a pinned, checksummed version, and this ADR says where that version comes from and what the repo may contain.

## Decision

The fleet repo is public. Tagged releases carry prebuilt binaries. The Template build installs the pinned fleetd through the mise `github:` backend.

- **Contents rule.** The repo holds no hostname, VPN address, private IP, token, credential or private infra detail. That covers code, tests, fixtures, docs, CI files, example configs and git history. Examples use reserved names such as `fleet.example.invalid`.
- **Config.** fleetd and the CLI read the server address and the token from env and files: `FLEET_SERVER_URL`, `FLEET_BOX_NAME`, `FLEET_TOKEN`, `/etc/fleetd/config.toml`. No default points at a real host. The wiring (`/etc/swarm/box.env`, the secrets file, the managed-settings file, the unit file) lives in the deployment repo, outside this one. The fleet repo may ship example unit and settings files that use only generic paths.
- **Enforcement.** CI runs a secret scanner and a pattern check for RFC 1918 ranges, the carrier-grade NAT range used by VPN overlays, and VPN domain suffixes. The check holds patterns, never real names, since a deny list of private hostnames would leak them.
- **Release assets.** cargo-dist builds the `fleetd` and `fleet-cli` packages for the same three targets: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` and `aarch64-apple-darwin`. Archives are named after the package, not the binary: `fleetd-<target>.tar.gz` holds `fleetd`, and `fleet-cli-<target>.tar.gz` holds `fleet`. Each has a `.sha256` file, and the release adds an aggregate `sha256.sum`. One target matrix for both packages avoids per-package target config. `fleet-server` and the library crates set `dist = false`. `fleet-server` ships as an OCI image built from the same tag.
- **mise on the boxes.** One `github:` entry cannot pick two tools from one release, and the `[tool_alias]` bracket form collapses two entries into one tool, so a Box declares a `[tool_alias]` section with `fleetd` and `fleet` both pointing at the repo, plus a `[tools.<name>]` entry each with an exact `asset_pattern` that names the target.
- **Verified.** On a Linux Box with mise 2026.8.12 and v0.1.0:
  - The `[tool_alias]` form works: both binaries install and print 0.1.0.
  - The bracketed form collapses both tools into one.
  - A wildcard `asset_pattern` ignores the platform and picked the macOS archive.
  - mise checked the sha256 from the GitHub API digest. The release has no attestations, so mise found none.
  - The `arch()` template pattern for aarch64 is untested.
- **Install.** The Template build runs `mise use` with the `github:` backend for fleetd at an exact version, and the laptop does the same for `fleet`. The version pin lives in the deployment repo. An upgrade is still a Template rebuild.
- **Licence.** Apache-2.0, chosen 2026-10-24. The repo carries a `LICENSE` file with the Apache-2.0 text before the first public push.

## Unverified

Check before the release pipeline is built, with a researcher run: how the `github:` backend picks one asset when a release holds several tools, whether `asset_pattern` or a per-tool name settles it, how it verifies a checksum or attestation, and its behaviour under GitHub API rate limits during a Template build.

## Decisions (2026-10-24)

- Accepted 2026-10-24.
- Licence: Apache-2.0.
- Repo owner and name: github.com/a19simma/fleet.
- Docs live in this repo.

## Consequences

- A committed secret or private name is public once pushed. History rewrite does not undo a clone. The first push needs a full scan, including `docs/phase0/`.
- The plan, ADRs 0011 to 0017 and the Phase 0 records live in this repo under `docs/`, in sanitized form (plan, decision 13).
- The server source is public. The shared bearer token (ADR-0014) never depended on secrecy of the code, so auth does not weaken. Security fixes land in public.
- Boxes need outbound access to GitHub at Template build time only, not at runtime.
- A broken release is public and visible. A pinned version limits the blast radius to the next Template build.
- A public issue tracker invites reports that may quote private output. The issue template says to redact.

## Considered and rejected

- **Private repo with private release assets.** A Box would need a GitHub credential to download, an additional credential on top of the Template's existing three. It also contradicts the requirement.
- **Build from source in the Template.** Needs a Rust toolchain and minutes of compile in the image, and a differently built binary per rebuild.
- **`cargo:` backend.** Same compile cost. Kept as a fallback only if no release asset fits, per the mise backend order.
- **`aqua:` registry.** Needs an upstream registry change before the first install.
- **`scp` from the laptop.** Not reproducible. Stays a development shortcut (plan, upgrade path).
