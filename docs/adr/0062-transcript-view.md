# Transcript view

Status: Proposed 2026-11-08. The `fleet_core::transcript` module, the pretty `fleet logs` and the web transcript view are built. Amends ADR-0022 (reading), builds on ADR-0055. Decision 2 is amended by ADR-0063.

ADR-0022 stores the stream-json output of a Job and serves it as raw lines. `fleet logs` prints those lines and the job page shows them in one `pre` block. A reader sees JSON, not the conversation. The web page also makes one `ReadTranscript` call with a 100-chunk limit, so a long Job is cut short without a marker.

## Decision

The server keeps storing raw stream-json. Both surfaces parse it at read time with one pure module in `fleet-core`.

1. **Parse at read time in `fleet_core::transcript`.** The module does no IO. Storage (`job_transcript`) stays raw stream-json, and the proto and `ReadTranscript` do not change. Precedent: ADR-0055 put `fleet_core::timing` in `fleet-core` for the CLI and the web to share, with a parity test and a GAPS list. This module gets the same pair.
2. **One sanitiser for every decoded string field.** `is_hostile`, the hostile ranges and `strip_keeping_lines` live in `fleet_core::text`, and ADR-0063 defines the set. For each field the order is: redact, strip hostile characters, redact again, strip again, then cut at the field cap. Renderers never touch a raw string.
3. **The web job page stays server-rendered Topcoat HTML with no new JS.** The CSP is `script-src 'self'` (ADR-0041), and styling uses literal class names and the committed `assets/ui.css` (ADR-0051). Tool calls are `details` elements. `?raw=1` shows the old `pre` block. A copy button and auto-refresh are deferred: each needs a new decision.
4. **Caps.** A line over 256 KiB (`MAX_CHUNK_BYTES`) is rejected before parsing. Text is cut at 16 KiB. Tool output is cut at 16 KiB with an "N bytes more" note. A command summary is 200 characters. A view holds at most 20,000 entries. Nesting depth is 8, and the `serde_json` recursion limit of 128 stays. A truncated chunk becomes a `Truncated` entry and is never parsed. A non-JSON line is a Fleet note only when it starts with the exact prefix `fleet: `.
5. **`fleet logs` defaults to the pretty view.** `--raw` keeps the previous output byte for byte. Compatibility: a script that parses raw lines must add `--raw`. Color is on only for a TTY. `-f` streams line by line.
6. **Unknown input degrades.** An unknown event type or shape becomes an `Unknown` entry. ADR-0044 names Codex and Kimi runners whose parsers do not exist yet, and their output must not break the view. The view parser is separate from the fleetd telemetry parser (ADR-0029) and, like it, never fails a read.
7. **The web page pages `ReadTranscript`.** It follows `after_seq` until `done`, the 4 MiB and 50,000-row ceiling of ADR-0022, or the render cap, whichever comes first. Today it makes one read with a 100-chunk limit.
8. **Chunk shape.** ADR-0022 says a chunk is a batch of lines up to 64 KiB, while the runner sends one line per chunk. The parser splits each chunk on newline and never joins lines across chunks.

### Entries

Terms are in `CONTEXT.md`. The parser turns each line into one **Transcript entry**: text, a **Tool pair** (a `tool_use` joined to its `tool_result` by id, shown as one unit, or alone when the other half is missing), a result with totals, a **Fleet note**, `Truncated` or `Unknown`.

Per-turn `usage` can repeat across assistant events that share a message id. The parser dedupes by message id and takes totals from `result.usage`.

## Consequences

- Redaction runs on raw JSON text before a line is stored. A secret written with JSON escapes (`\uXXXX`) can survive the exact-value redactor and decode into plain text in the view. The view redacts decoded fields only where a redactor is available: the CLI has only a client-token redactor and the web has none. This is a documented limit under the Sensitivity bullet of ADR-0022 and is not fixed here.
- Claude stream-json shape can drift. `Unknown` entries keep the view readable when it does.
- The CLI and the web share one parser and cannot drift in what they show, and a parity test pins that.
- `fleet logs` output changes for every caller that does not pass `--raw`.
- The web page makes several `ReadTranscript` calls for a long Job instead of one.
- Nothing here is verified against a live run.

## Considered and rejected

- **Client-side JS parse.** JS becomes the security boundary, the CLI needs its own parser anyway, and the two surfaces drift.
- **Server-side typed proto.** Needs a proto change, adds a second parser in the server, and commits the stored format.
- **Parse at ingest.** Loses the raw stream and freezes the model.
