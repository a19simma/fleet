# Baked default update trust root

Status: Proposed 2026-11-01. Built in `crates/fleetd/src/update.rs`, verified on the dev box on 2026-11-08 against the signed v0.3.8 manifest. Amends ADR-0047.

ADR-0047 fixed the update trust root as a file, `/etc/fleetd/update.pub`, that every Box had to hold. A Box without that file could not verify a manifest, so a fresh Template did nothing until an operator installed the file. This ADR gives fleetd a default key inside the binary and keeps the file as an override. Commit 27567fe edited the trust-root lines of ADR-0047 in place to match.

## Decision

### Where the key comes from

- fleetd embeds a minisign public key at build time from `crates/fleetd/trust/update.pub` (`BAKED_TRUST_KEY`). A Box needs no key file.
- When `/etc/fleetd/update.pub` exists it replaces the embedded key. The file must be a regular file, root-owned, with no group or other write bit, in a parent directory with the same properties.
- A file that is present and fails any check disables updating. fleetd never falls back to the embedded key. Only a file that does not exist selects the embedded key.
- `update_trust_root` set in the config file makes that path required. A missing file then disables updating, and so does an unsafe or invalid one.
- The key that verifies the bundled mise binary (`public_key_path` in `[mise]`, `crates/fleetd/src/tools.rs`) stays file-only. The embedded key and `update.pub` do not change it.

### Consistency check in CI

- The `update-key` job in `ci.yml` compares line 2 of `crates/fleetd/trust/update.pub` with the repository variable `FLEET_UPDATE_PUBLIC_KEY`.
- The `update-key` job skips its comparison step when the variable is empty.
- The release workflow runs the same comparison and fails a tag build when the variable is empty. On other runs an empty variable logs a notice and skips the check. The Verify step of the manifest-signing job also logs a notice and passes when the variable is empty, so the signature is then unverified in CI.

### Rotation

The embedded key changes only with a new fleetd build. The signing key and the baked key are one key, with no rollover.

1. Ship a release signed with the OLD key whose binary bakes the NEW key.
2. Wait until every Box runs that release.
3. Switch the repository secret `FLEET_UPDATE_SIGNING_KEY` and the variable `FLEET_UPDATE_PUBLIC_KEY` to the new key.
4. Sign later manifests with the new key.

A Box that holds an override file keeps trusting that file and wins over the new embedded key. Remove the override before step 3.

### Compromised key

A compromised signing key has no safe in-band route. An attacker who holds the old key can sign the step 1 release too. The routes are to push `/etc/fleetd/update.pub` with the new key to each Box as root, or to rebuild the Template and replace the Boxes. A Box that took a malicious binary runs it as `fleetd`, so treat that Box and its credentials as lost.

## Options

| Option | Verdict | Reason |
| --- | --- | --- |
| Fixed file trust anchor only (ADR-0047 as first written) | Replaced | Every Box needs a file before it can update. A Template that forgets the file never updates. |
| Embedded key plus file override | Chosen | A fresh Box verifies at once. The override keeps a root-controlled route for a compromised key. |
| Key read by `build.rs` | Rejected | Adds a build step that reads a path or fetches a value, and a stale or missing input changes the shipped key without a source diff. `include_str!` of a tracked file shows the key in the diff and in review. |
| Key from an environment variable at build time | Rejected | The key then lives outside the repository, so a local build and a CI build can bake different keys and nothing in the tree records which. |
| Fall back to the embedded key on a bad override | Rejected | An attacker who can corrupt the file would downgrade the root to the default. Failing closed leaves the Box on its running version. |

## Consequences

- A Box verifies updates with no setup. This is the gain over the fixed file anchor.
- Key rotation needs a release. Under the file anchor an operator replaced one file per Box. Now the key changes by shipping a signed release and waiting for every Box, which is slower and fails for a Box that never updates.
- A stale override wins after a rotation. The operator removes it, or that Box stops accepting new manifests with a `Signature` error and stays on its running version.
- A Template rebuild resets a Box to the baked binary and its embedded key.
- The CI check ties the repository variable to the tracked key, so the key in the binary and the key the release workflow verifies with cannot drift unnoticed on a tag build.

## Unverified

- Answered 2026-11-08: the dev box verified the signed v0.3.8 manifest with the baked key. The key id to check against the published files is `B4880B1AF20089CF` with `minisign -V` against the published `manifest.json` and `manifest.json.minisig`.
