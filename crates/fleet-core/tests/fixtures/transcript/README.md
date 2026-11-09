# Transcript fixtures

Hand-written golden inputs for `fleet_core::transcript`. Each `.jsonl` file is one Job transcript: one JSON object per line in the shape of `claude -p --output-format stream-json`. fleetd may append a trailing non-JSON line `fleet: no_changes`. All ids, uuids and session ids are fake. Paths use `/work/repo`.

Every line parses as JSON except the documented exceptions: the last line of `truncated_chunk.jsonl`, and any line starting with `fleet: `.

## Files

| File | Covers |
| --- | --- |
| `sample_job.jsonl` | hook_started and hook_response, init, rate_limit_event, two turns (Bash call, Read call) with results, final result, trailing `fleet: no_changes` |
| `subagent.jsonl` | Task call; child assistant and user events carry `parent_tool_use_id` equal to the Task tool_use id |
| `thinking.jsonl` | `thinking` content blocks with signature |
| `result_block_array.jsonl` | tool_result `content` as an array of text blocks plus one `image` block |
| `error_result.jsonl` | tool_result with `is_error` true; final result with `is_error` true |
| `denial.jsonl` | final result with one entry in `permission_denials` |
| `interleaved_calls.jsonl` | two tool_use in flight, results arrive in reverse order |
| `call_without_result.jsonl` | tool_use never answered, no final result |
| `result_without_call.jsonl` | tool_result whose tool_use_id has no earlier tool_use |
| `duplicate_ids.jsonl` | a repeated message id with different usage, a second tool_use and a second tool_result with the same id |
| `late_call.jsonl` | a tool_result whose tool_use arrives later, then a second result for the same id |
| `truncated_chunk.jsonl` | last line cut mid-JSON (invalid), as the runner's 256 KiB cut leaves |
| `unknown_top_level.jsonl` | a `{"type":"future_thing",...}` line |
| `unknown_subtype.jsonl` | a system line with an unseen subtype |
| `unknown_block.jsonl` | an assistant content block of unseen type `citation_x` |
| `hostile_values.txt` | hostile strings for sanitiser tests, see below |

## hostile_values.txt

One case per line: `label`, a TAB, then the value. The value is ASCII only and is decoded by the test:

- `\uXXXX` (four hex digits) is one UTF-16 code unit. A high surrogate followed by a low surrogate forms one code point.
- `<LONG:N>` as the whole value means a string of N `a` characters (an over-long line marker). `<LONG:70000>` is over the 16 KiB text cut and under the 256 KiB `MAX_CHUNK_BYTES` line cap.
- An empty value (nothing after the TAB) is the empty string.
- There is no other escape syntax. The values contain no literal backslash.

Labels: cr, crlf, nel, line_sep, para_sep, bidi_rlo, bidi_lri, ansi_sgr, osc8, nul, script, md_link, html_entity, overlong, empty, non_ascii.
