# Job timing breakdown and loopback OTLP receiver

Status: Proposed 2026-11-02. Not built. Loopback reachability (TIM-F11): probe written, not yet run on a live host. Supersedes the "Not built" bullet of ADR-0029 (no OTLP receiver, no pueue). Amends ADR-0029 and ADR-0031.

Supersedes: the "No OTLP receiver, no pueue, no wrapper around Bash" bullet of ADR-0029, in part. The no-wrapper rule stays.

ADR-0029 records turns, cost and tool counts. It cannot say where a Job's wall time went. The stream-json output has no per-tool duration, and `result.duration_api_ms` is one aggregate for the whole run. The `PostToolUse` hook of ADR-0029 tier B gives a duration for foreground tools only. A background Bash command has no completion event in any of these sources. ADR-0029 rejected an OTLP receiver and pueue because the hooks covered the exit code. They do not cover time, so this ADR reverses that choice for timing.

## Decision

Each Job reports a timing breakdown of five parts that sum to its wall time: `api_wait`, `tool`, `shell`, `idle` and `overhead`. fleetd collects spans from three sources, reconciles them in `fleet-core`, and the server stores and re-checks the result.

### Sources

- **Claude: loopback OTLP receiver.** fleetd runs one OTLP/HTTP receiver per Job, bound to `127.0.0.1:0`. It accepts only `POST /v1/logs` with `Content-Type: application/json` and a per-Job bearer token. It reads at most `cap + 1` bytes of body and answers 413 above the cap, refuses a chunked body over the cap, caps concurrent connections, and refuses any peer that is not loopback. The token is random per Job and never reaches a log line or argv.
- **Claude events used.** `api_request` gives an API wait span of `duration_ms` ending at the event time. `tool_result` gives a tool span of `duration_ms`, with the `Bash` tool counted as shell. `tool_decision` carries `tool_use_id` and joins to `tool_result` on it. Other events are skipped and counted.
- **Kimi: `wire.jsonl`.** fleetd tails the Kimi session `wire.jsonl` and pairs `llm.request` with `usage.record` into API wait spans. The field names of those two records are unverified: no Kimi documentation or captured run has been read for this ADR. TIM-F5 requires a fixture captured from a real Kimi run before the parser is written, and the parser skips and counts any unknown line.
- **Shell and background commands.** Each shell command is recorded as a redacted command, a bounded redacted log, a start, an end and a duration. Foreground Bash takes start and end from the `tool_result` span. A background command has no completion event, so fleetd measures it. For `pueue add` fleetd reads the task start and end timestamps from `pueue status --json` itself, with a monotonic fallback when pueue gives none, and captures the log with a byte cap. For a Claude `run_in_background` Bash task, which has OTel timing only, the span ends when the task ends or when the Job does.
- **Outliving tasks.** A Claude `run_in_background` Bash task that outlives the Job is recorded with `ended_by=job_exit` and the OTel timing only. The owner accepted this loss of a true end time.
- **Redaction.** The command and the log pass the `fleet-core` redactor before they are cut to their caps, as in ADR-0029.

### Claude configuration

fleetd sets these variables on the `claude` child. The names are confirmed against the Claude Code monitoring page, fetched 2026-11-02 by a researcher agent: [Monitoring usage](https://code.claude.com/docs/en/monitoring-usage), official docs.

| Variable | Value | Quoted from the page |
|---|---|---|
| `CLAUDE_CODE_ENABLE_TELEMETRY` | `1` | `export CLAUDE_CODE_ENABLE_TELEMETRY=1` |
| `OTEL_LOGS_EXPORTER` | `otlp` | "Logs/events exporter types, comma-separated. Use `none` to disable" |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/json` | "Claude Code has no default protocol, so set this or the signal-specific protocol variable for each `otlp` exporter you enable" |
| `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` | `http://127.0.0.1:<port>/v1/logs` | "OTLP logs endpoint, overrides general setting", example `http://localhost:4318/v1/logs` |
| `OTEL_EXPORTER_OTLP_HEADERS` | `Authorization=Bearer <token>` | "Authentication headers for OTLP", example `Authorization=Bearer token` |
| `OTEL_LOGS_EXPORT_INTERVAL` | `1000` | "Logs export interval in milliseconds (default: 5000)" |
| `OTEL_LOG_TOOL_DETAILS` | `1` | "Enable logging of tool parameters and input arguments in tool events and trace span attributes: Bash commands, MCP server and tool names, skill names, user-authored workflow names, and tool input." Default disabled. |

- **Endpoint path.** The page shows `/v1/logs` only in the example for the logs endpoint variable. It does not say whether Claude Code appends the path when only `OTEL_EXPORTER_OTLP_ENDPOINT` is set, and that is unverified. fleetd sets the logs endpoint variable with the full path, which avoids the question. The OTLP spec names the same path: "The default URL path for requests that carry log data is `/v1/logs`" ([OTLP/HTTP Request](https://opentelemetry.io/docs/specs/otlp/#otlphttp-request), official docs).
- **Event attributes.** `tool_result` and `tool_decision` carry `tool_use_id`: "Matches the `tool_use_id` passed to hooks, allowing correlation between OTel events and hook-captured data." `duration_ms` is on `api_request` ("Request duration in milliseconds") and `tool_result` ("Execution time in milliseconds") and not on `tool_decision`. `success` on `tool_result` is documented as the string `"true"` or `"false"`. The page marks `tool_input` as "bounded to ~4 K characters".
- **Interval and flush.** The 1 s interval keeps the tail small. fleetd flushes at Job exit: it waits until in-flight bodies are queued and no body has arrived for 1.5 s, or a named deadline, and records `incomplete` when the deadline fires.
- **Job-supplied overrides.** The Job env builder refuses any `OTEL_*` name and `CLAUDE_CODE_ENABLE_TELEMETRY` from a Profile or Job, so a Job cannot redirect or switch off the exporter.

### OTLP/JSON encoding

The Claude page says nothing about the wire format. The rules below come from the OTLP spec, [JSON Protobuf Encoding](https://opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding), official docs:

- "64-bit integer numbers (`int64`, `sint64`, `uint64`, `fixed64`, `sfixed64`) in JSON-encoded payloads are encoded as decimal strings"
- "The keys of JSON objects are field names converted to lowerCamelCase."
- "The client and the server MUST set 'Content-Type: application/json' request and response headers when sending JSON Protobuf encoded payload."

The parser reads an int value as a string or a number and rejects an out-of-range one. The `resourceLogs`, `scopeLogs` and `logRecords` nesting and the `AnyValue` attribute forms (`stringValue`, `intValue`, `boolValue`) come from the OTLP logs proto and were not fetched for this ADR. They are unverified until TIM-F3 pins them with a fixture captured from a real Claude Code run.

### Reconciliation

Terms: **wall** is the Job window, claim to finish. The **agent window** is the span from agent child start to its exit. Spans are intervals clamped to the agent window.

1. Merge the intervals of each kind: `Shell` and `BgShell` together, `Tool`, `ApiWait`.
2. On overlap, `Shell` and `BgShell` beat `Tool`, and `Tool` beats `ApiWait`. Each instant counts once, for its highest kind.
3. `idle` is agent window time covered by no span.
4. `overhead` is wall minus the agent window: clone, setup, push, pull request and teardown.
5. `api_wait + tool + shell + idle + overhead = wall` by construction, from merged intervals and subtraction. A parallel subagent span that overlaps another merges instead of adding twice.

`fleet-core` owns the function. The server recomputes it from the received spans and refuses a summary that differs, whose parts do not sum to wall, or whose spans fall outside the Job window.

### Failure handling

Capture never fails a Job. A receiver bind failure, a parse error or a flush deadline records a timing note and the report goes out with what exists. A Job with no report shows an absent state, never zeros.

## Risk: sandbox loopback reachability

ADR-0031 P2 sets `PrivateNetwork=yes` on `fleet-agent@.service`. Inside that namespace, `127.0.0.1` is the namespace loopback, and the hook port of fleetd is unreachable (ADR-0031, Hooks). A receiver bound on the host loopback is unreachable by the same rule. Under the systemd launcher the OTLP endpoint therefore fails unless it travels the route the egress proxy uses: a listener inside `agent-exec` that forwards to a socket under the Job directory. `RestrictAddressFamilies` is a second possible block, which ADR-0031 hit as a failed `socket()` when `AF_INET` was missing.

Inferred, not part of the design: the receiver listens on the Job unix socket and `agent-exec` forwards a namespace loopback port to it, as the egress forwarder does. TIM-F11 probes this against the real `fleet-agent@` unit directives: one probe per directive, each with a positive control, run on a live host. The result is recorded in this ADR or in `.ralph/progress.md`, and the design above stays Proposed until the probe passes. **TIM-F11 result: probe written, not yet run on a live host.** `deploy/probe-agent-loopback.sh` reads the sandbox directives of the installed `fleet-agent@.service`, starts a host listener on `127.0.0.1` and on a unix socket, and runs the workload as transient units through `systemd-run`, one directive varied per probe, each with a positive control that fails the run when its precondition is absent. It prints PASS or FAIL per transport (`loopback-tcp`, `unix-socket`). The agent never ran it: this was written on macOS. Owner command on a Box, as root, with the unit installed: `sudo deploy/probe-agent-loopback.sh`.

Static prediction from the unit file: `deploy/fleet-agent@.service` line 28 sets `PrivateNetwork=yes`, which gives the unit its own network namespace with only its own `lo`, so host `127.0.0.1` is unreachable and loopback TCP should FAIL. Line 30 `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` allows `socket()` for both families, so it blocks neither transport. The unit sets no `IPAddressAllow` or `IPAddressDeny`. Unix sockets are filesystem objects and cross the namespace: line 34 `ReadWritePaths=/var/lib/fleet/jobs` and line 42 `BindPaths=/run/fleet/%i` keep the Job directory reachable, so the unix socket should PASS. The ADR-0031 live run records the same: a connection to host `127.0.0.1:7071` was refused while in-namespace loopback and unix sockets worked.

Default if the probe cannot be run: a unix socket under the Job directory, with `agent-exec` forwarding a namespace-loopback port to it as the egress forwarder does (`crates/fleetd/src/agent_exec.rs`). Host loopback TCP stays the choice only under the `direct` launcher. Status stays Proposed.

Under the `direct` launcher no namespace separates the child from fleetd, and the host loopback works.

Security of the receiver itself: any process on the Box can reach a host loopback port. The per-Job bearer token and the loopback peer check limit a report to a holder of that token. A Job that reads its own environment holds its own token and can post forged timing for itself. Accepted: the figures describe the Job's own run and gate nothing.

## Consequences

- fleetd gains an HTTP receiver, an OTLP parser, a pueue poller and a Kimi wire parser. Each is a pure parser or an injected client, so each has a table test.
- `ReportTiming` and `GetJobTiming` are new RPCs. Reporting needs the box token and a live lease on the Job. Reading needs the client token.
- The server stores spans and shell commands per Job, and retention removes them with the Job.
- Claude events carry tool parameters when `OTEL_LOG_TOOL_DETAILS=1`. The receiver redacts the command before it stores or forwards it, and the raw event body is never kept.
- Not covered: a background task that outlives the Job has no end time, and Kimi timing waits on a captured fixture.
