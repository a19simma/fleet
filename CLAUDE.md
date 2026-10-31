# Fleet

Rust workspace: `fleetd` (box daemon), `fleet-server` (gRPC on Postgres), `fleet` CLI, shared `fleet-core` and `fleet-proto`. Design lives in `docs/plan.md` and `docs/adr/`. Read the ADRs that touch your change before editing.

## Verify

Run the project verify before every commit: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --no-fail-fast`, and the private-pattern scan below. Server tests need `DATABASE_URL` pointing at Postgres 17 (`#[sqlx::test]`).

## Common review failures

These sent earlier work back for a retry. Check each before you commit.

1. **Commit message.** One semantic commit, `type(scope): subject`, subject at most 72 characters (count it), lowercase, imperative, no trailing period. No `Co-Authored-By`, no session or tool links, no attribution of any kind. A retry squashes into one commit.
2. **Timing tests.** Use tokio paused time (`test-util` is a dev-dependency). Paused time does not work around sqlx: the pool's own timers and acquire timeout (30 s) fire whenever the runtime idles on blocking IO, so virtual time races ahead and a test sees `PoolTimedOut` or jumps of minutes. For a loop that touches the Store, use real time with a wait of 5 s and a not-yet check at 500 ms. The same holds for client timeouts and keepalive over real sockets in a paused test: the clock jumps while a reply is in flight and the timer fires. Call `run_with(.., false, ..)` in such tests. In a timeout test, call `tokio::time::pause()` only after the server has seen the connection.
3. **Raw client input in errors.** Never echo a client-supplied value (box name, token, path) into a `Status` message, `Rejection.reason`, or a log line at a level clients can read. Use a fixed message.
4. **Inferred claims written as fact.** In ADRs and docs, label anything not in the design as "Inferred, not part of the design:". No hedges (`should`, `probably`, `enough`), no em dashes, no "not X but Y".
5. **Duplicate validation.** Validate each input once, at the boundary, and carry the validated type. A second check in a service handler gets flagged.
6. **Drift in comments and docs.** When behaviour changes, rewrite the rustdoc that described the old behaviour, ADR status lines, and `docs/adr/README.md` rows in the same commit. On any claim or status change, grep `docs/`, `docs/plan.md`, READMEs and crate docs for the feature name and the old wording and fix every hit in one pass: scattered status lines cost A11 and A18 up to five gate rounds. An ADR says a feature is built only when a runtime path calls it; library-only code stays "built, not wired".
7. **Lints.** CI clippy is newer than most local toolchains: no `unwrap` or `expect` in tests without `#[expect(lint, reason = "...")]`, keep the first doc paragraph short, and every new test file starts with a `//!` crate doc (`missing_docs` is `warn` in the workspace lints, so `-D warnings` fails without it), and avoid `pub` items in private modules (`unreachable_pub` and `redundant_pub_crate` conflict: use `#[expect]`). A fake in a private trait's test impl that never awaits trips `unused_async_trait_impl`: return `std::future::ready(..)` from a plain `fn`.

## Style

- Tracked files must not contain private hostnames, tailnet addresses and domains, home-directory paths, or box names with a digit suffix. CI greps for them and fails. Run the private-pattern grep over the diff before committing, and write "the dev box" in docs, never a box name (PF-5 failed verify on a box name in an ADR note).

## Keep this file current

When you hit a problem that cost you a retry, or a gate or CI failure you did not expect, add a short note in the nearest `CLAUDE.md`: the repo root for repo-wide traps, `crates/<name>/CLAUDE.md` for a crate-specific one. Write the symptom, the cause, and the fix in two or three lines. Add to an existing item instead of duplicating it. Remove a note once the code makes it impossible to hit.
