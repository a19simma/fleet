# Profile ownership and visibility

Status: Proposed 2026-11-02. Built: migration 0023 gives each Profile an `owner_user_id` and a `visibility`, and `profiles::create_owned`, `ShareProfile` and `UnshareProfile` scope by them. Amends ADR-0034 (Profiles have no owner), ADR-0035 (profile RPCs and storage are unscoped) and ADR-0048 (the `tools` gate meets owner scoping). Builds on ADR-0042 (users and Job ownership).

ADR-0034 and ADR-0035 store Profiles by name with no owner. Any client caller lists, reads and creates any Profile. ADR-0042 made Jobs and credentials owner-scoped but left Profiles out. With several users, one user can read another user's prompt text and context files, and nothing says who may change a name. This ADR gives each Profile an owner and a visibility.

## Decision

### Owner

- A Profile is owned by one User. The owner is set when the name is first created and never changes.
- Only the owner creates new versions, publishes a version or changes visibility. A non-owner mutation is refused.
- A Profile name is unique per owner. Two users can hold the same name.
- A Job pins a Profile version and hash (ADR-0034). That pin does not change when visibility changes later.

### Visibility

Visibility is `private` or `shared`. A new Profile is `private`.

- `private`: only the owner lists, reads or submits with it.
- `shared`: every authenticated User lists, reads and submits with it. A non-owner has read-only access. A non-owner cannot create a version, publish, change visibility or delete.

### Sharing by published version

- A version is a draft until the owner publishes it. Publishing is one way: a published version is immutable, as ADR-0034 already requires for every version.
- Sharing exposes published versions only. A draft is visible to the owner alone, even when the Profile is `shared`.
- A non-owner `GetProfile` without a version returns the latest published version. A non-owner naming a draft version gets the same answer as an unknown version.
- A Profile with no published version has nothing to share. A non-owner sees no entry for it in `ListProfiles`.
- `SubmitBatch` and Job submit by a non-owner accept only published versions of a shared Profile.

### Error shape

A non-owner `GetProfile` of a `private` Profile returns `NOT_FOUND` with the same fixed message as an unknown name. It never returns `PERMISSION_DENIED`, so a caller cannot probe which names exist. This matches the rule for another user's Job in ADR-0042.

`PERMISSION_DENIED` stays for one case: a non-owner who can see a `shared` Profile and tries to mutate it. The caller already knows the name, so nothing leaks. `fleet profile item` and `fleet profile prompt` send `CreateProfile` with `edit` set, so the same refusal applies to them: the CLI does not save a copy under the caller's own name, and the web selection post refuses the same way. A user who wants a copy creates one explicitly under a new name.

### Box and legacy callers

- The box token carries no user and reads every Profile blob for a leased Job (ADR-0035). That scope is unchanged. `GetProfileBlob` stays authorised against the lease.
- Profiles that exist before this ADR have no owner. A migration assigns them to a system user, marks them `shared`, and marks every existing version published. Not built: the draft and publish step, and so the marking. Migration 0023 assigns legacy Profiles to the system user and marks them `shared`, and no code carries a published flag. A later task that builds publishing must mark each legacy version published in its own migration, or this ADR is amended to drop the draft state. The system user cannot log in and holds no token. Nobody can mutate a legacy Profile, which matches today's rule that versions are immutable. A user who wants to change one copies it under their own name.
- The bootstrap user and the legacy client token (ADR-0042) are not owners of legacy Profiles. They read them as any other user does.

### ADR-0048 gate

The `tools` field stays behind the server config switch. The switch applies to every owner. Owner scoping adds no per-user permission, because the server still has no such scope.

## Consequences

- A user's prompt text and context files stay private until the owner publishes a version of a `shared` Profile.
- Names no longer collide across users. Batch and Job submit resolve a name against the caller's own Profiles first, then shared ones. A caller who owns the name and a shared name from another user gets their own.
- `ListProfiles` returns the caller's Profiles and the published versions of shared ones, so its page and cursor rules follow that union.
- Existing Jobs and hashes do not change. The Profile hash covers content only, so owner and visibility stay out of it.
- Making a Profile `private` again does not recall Jobs that already ran with a shared version. Those Jobs keep their pin.

## Deferred

- Per-user or per-group sharing.
- Transfer of ownership.
- Deleting a Profile.
- Showing the owner's name to non-owners.

## Considered and rejected

- **Org-wide edit.** Any user edits any shared Profile. A shared Profile then has no stable content for a comparison, and one user can change what another user's Jobs run. Versions are immutable already, so edit would mean new versions by strangers under the owner's name.
- **ACL lists.** Per-Profile lists of users and rights. The server has two token scopes and one user table, and no group model. An ACL adds a rights editor, a lookup on every read and a revocation story, for a team that needs two states. `private` and `shared` cover the stated need. Per-user sharing stays deferred.
- **`PERMISSION_DENIED` for a private Profile.** It confirms the name exists. ADR-0042 already chose `NOT_FOUND` for Jobs.
- **Sharing drafts.** A draft can still change its mind. Sharing only published versions means a reader sees content that cannot change under them.
- **A global name space with first-come ownership.** A user could squat a common name and block others.
