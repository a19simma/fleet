# Global catalog and profile selection

Status: Proposed 2026-11-02. Save-time selection validation, a re-save equal to an older version moving "latest", the `fleet profile item` and `fleet profile prompt` commands, the Kimi dropped-subagent notes in the job event stream, and the web profile page selection editor (toggles per kind, authored prompt) are built, as are the Catalog store, its admin RPCs and pages, `fleet_core::catalog::resolve` and the submit snapshot. Not built: the Profile preview, and showing the snapshot notes on `fleet show` and in the web job view. Amends ADR-0034 (what a Profile holds) and ADR-0035 (what the hash covers). Builds on ADR-0044 and ADR-0048. Tool items need the owner capability `profile:tools` of ADR-0054.

ADR-0034 defines a Profile as a bundle of content: `claude_md`, inline skills, context files and rules. Every Profile repeats the content it needs, and nothing says which skills, subagents or tools exist on the server. This ADR adds a server-managed catalog and turns a Profile into a selection over it.

## Decision

### Catalog

The **Catalog** is one global list of items, curated by an admin. An item has a kind, an id, a body and an `enabled` flag that only an admin sets. The kinds are:

- `skill`: a name and files, as in ADR-0034.
- `subagent`: a name, a prompt and a tool list.
- `tool`: a `{name, version}` entry from the registry of ADR-0048.
- `context`: a path and text, laid out as in ADR-0034.

Items are insert-only and versioned like Profile blobs (ADR-0035). Changing an item adds a version. An admin disables an item by clearing `enabled`, never by deleting it.

Only an admin lists the Catalog, on both surfaces: `ListCatalog` answers `PERMISSION_DENIED` with `admin required` to any other caller, and the admin page answers 403. Both show every item, admin-disabled ones included.

### Selection is opt-out

A Profile does not list the items it wants. It inherits every item that is enabled in the Catalog. The Profile stores only:

- `disabled`: the item ids the user switched off.
- The user-authored prompt text: `claude_md`, `prompt_prefix` and `prompt_template`.

The other ADR-0034 fields stay as they are. The `skills`, `context_files` and `tools` content fields move out of the Profile into the Catalog, and the Profile hash covers `disabled` and the authored text. The hash prefix for this shape is `fleet-profile-v3\0`, so existing v1 and v2 hashes stay valid.

The owner said: "there's a global list of available ones but the user can turn them off selectively". Opt-out follows that statement.

### Resolve

`fleet_core::catalog::resolve(catalog, profile)` is a pure function. It takes the Catalog rows and one Profile and returns the **effective set**:

1. Drop every item that is not `enabled` in the Catalog.
2. Drop every item whose id is in the Profile `disabled` list.
3. For a `tool` item, keep it only when the Profile owner holds `profile:tools` (ADR-0054). Otherwise drop it and add a job note.
4. When the job agent is `kimi` (ADR-0044), drop every `subagent` item and add a visible job note that names each dropped item. The Kimi runner has no subagent mechanism.
5. Return the kept items in id order, plus the notes.

The function reads no clock, database or environment. A `disabled` id that is not in the Catalog makes `resolve` return `ResolveError::UnknownItem`. A `disabled` id for a Catalog item that is not `enabled` is dropped with the rest of that item.

### Save validates the selection

A Profile save (create or new version) checks `disabled` against the Catalog in the save transaction. One keyed read takes the named Catalog rows `FOR SHARE`, bounded by the selection cap `MAX_SELECTION` (256), so an admin edit in flight finishes first and a later one waits for the save. The save first refuses a `tools` content list from a user without `profile:tools` (`ToolsNotGranted`), then refuses on the selection faults below, checked in this order:

- an id has no Catalog row (`InvalidProfile(UnknownItem)`),
- an id names an item an admin disabled (`InvalidProfile(ItemDisabled)`), or
- an id names a `tool` item and the owner lacks `profile:tools`, read `FOR SHARE` in the same transaction (`ToolsNotGranted`, ADR-0054).

The faults come in that order and none echoes the id. Save diverges from submit here: submit drops a disabled id, because an admin can disable an item after the save, but a save that names one is a mistake worth failing early. Resolve drops the item when an admin later disables it. An id that later leaves the Catalog makes `resolve` fail with `ResolveError::UnknownItem`, and submit refuses the job with the snapshot error (`JobInvalid::Snapshot`).

### Submit and snapshot

The server calls `resolve` at submit, in the same transaction that inserts the Job. The effective set and the notes are stored on the Job as an immutable snapshot, with the Catalog item versions it used. `GetProfileBlob` (ADR-0035) returns the snapshot, and fleetd overlays it as in ADR-0034. fleetd re-validates it with the shared validator and applies the Floor and the Box ceilings last. A later Catalog change never alters a queued or running Job.

Job notes show on `fleet show` and in the web job view next to the Job status. A dropped Kimi subagent is a note, not a failure.

Built: fleetd re-resolves the selection against the validated blob catalog only to name the Kimi subagents the runner drops. Each dropped item gets one `phase` event in the job event stream; more than 64 collapse into one "and N more dropped" event. The events count against the per-job event cap (`MAX_EVENTS_PER_JOB`). The server stores the snapshot notes, but showing them on `fleet show` and in the web job view is not built.

### Consequence of opt-out

An item that an admin enables reaches every Profile at its next submit, with no action by the Profile owner. That includes a Profile that has not changed in months. Two mitigations:

- The submit snapshot makes each Job stable. A queued or running Job keeps the set it was resolved with, so a Catalog change cannot shift a Job mid-flight.
- The Profile preview lists the effective set and its diff against the set of the user's last submitted Job: items added, items removed and items dropped with a reason. A user sees a new item before they submit.

An admin who wants a new item off by default has no switch for it in this design. The item reaches everyone, and users turn it off.

### Floor and tools

The Floor is unchanged. A Catalog item cannot loosen it, and a `subagent` tool list passes the same allow and deny clamp as a Profile `allow` list. A `tool` item still installs through the bundled mise of ADR-0048 with the registry, pinned versions and Box-only egress that ADR sets.

## Consequences

- A Profile shrinks to a few fields and a list of ids. Two Profiles differ by what they switch off and by their prompt text.
- Skill, subagent and context content is stored once and versioned once.
- Each Job records exactly what ran: the effective set, the item versions and the notes.
- A Catalog edit changes the future of every Profile. Admin review of an item is the control point, and the preview is the user's.
- The Profile hash no longer covers Catalog content. The Job snapshot is the record of that content.
- The server keeps one version per distinct content. A save equal to an older version returns that version with `created` false and moves "latest" to it (`profile.latest_version`), so switching an item off and on again returns the Profile to its first version. The history keeps one row per hash.

## Considered and rejected

- **Opt-in selection** (`{item_id, enabled}` entries that a user adds). It keeps every Profile unchanged when an admin adds an item, and a Profile hash then covers the exact selection. It was rejected because the owner wants one global list with selective switch-off, and opt-in makes every user pick each item by hand.
- **Resolve at fleetd.** It needs the Catalog on every Box and makes the result depend on Box state. Resolve at submit keeps it pure and in one place. The fleetd resolve that is built is narrow: it only names dropped Kimi subagents for notes and never changes what the Job runs.
- **Resolve at claim time.** A queued Job would change between submit and start.
- **Failing a Kimi Job that has subagent items.** The Profile is valid for other agents, so a visible note is enough.
- **Per-Profile Catalog copies.** It is the bundle model this ADR replaces.
