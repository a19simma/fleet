# Fleet

Rust workspace: `fleetd` (box daemon), `fleet-server` (gRPC on Postgres), `fleet` CLI, shared `fleet-core` and `fleet-proto`. Design lives in `docs/plan.md` and `docs/adr/`. Read the ADRs that touch your change before editing.

## Verify

Run the project verify before every commit: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --no-fail-fast`, and the private-pattern scan below. Server tests need `DATABASE_URL` pointing at Postgres 17 (`#[sqlx::test]`).

## Common review failures

These sent earlier work back for a retry. Check each before you commit.

1. **Commit message.** One semantic commit, `type(scope): subject`, subject at most 72 characters (count it), lowercase, imperative, no trailing period. No `Co-Authored-By`, no session or tool links, no attribution of any kind. A retry squashes into one commit.
2. **Tests never seen red.** Write the test first, run it against the old behaviour, and say in the report whether it failed. A test that passes on old code proves nothing. Prefer mutating the fix (revert it, watch the test fail) over trusting the assertion.
3. **Timing tests.** Use tokio paused time (`test-util` is a dev-dependency) and wide bands. Wall-clock margins under 10x flake in CI. Paused time does not work around sqlx: the pool's own timers and acquire timeout (30 s) fire whenever the runtime idles on blocking IO, so virtual time races ahead and a test sees `PoolTimedOut` or jumps of minutes. For a loop that touches the Store, use real time with a wait of 5 s and a not-yet check at 500 ms.
4. **Raw client input in errors.** Never echo a client-supplied value (box name, token, path) into a `Status` message, `Rejection.reason`, or a log line at a level clients can read. Use a fixed message.
5. **Inferred claims written as fact.** In ADRs and docs, label anything not in the design as "Inferred, not part of the design:". No hedges (`should`, `probably`, `enough`), no em dashes, no "not X but Y".
6. **Error paths skipping cleanup.** `?` before `pool.close()` or a socket drop skips the cleanup. Run cleanup first, return the error after.
7. **Duplicate validation.** Validate each input once, at the boundary, and carry the validated type. A second check in a service handler gets flagged.
8. **Drift in comments and docs.** When behaviour changes, rewrite the rustdoc that described the old behaviour, ADR status lines, and `docs/adr/README.md` rows in the same commit.
9. **Test binaries that spawn and bind.** On macOS a test binary that both spawns child processes and creates or drops unix sockets can leak fds to the child. Put spawn tests in their own file under `tests/`.
10. **Lints.** CI clippy is newer than most local toolchains: no `unwrap` or `expect` in tests without `#[expect(lint, reason = "...")]`, keep the first doc paragraph short, and avoid `pub` items in private modules (`unreachable_pub` and `redundant_pub_crate` conflict: use `#[expect]`).

## Style

- No inline comments. The one exception is `// SAFETY:` above `unsafe`. Use rustdoc on public items.
- Lint rules are obeyed or disabled in config. The only in-code escape is `#[expect(lint, reason = "...")]`.
- Tracked files must not contain private hostnames, tailnet addresses and domains, home-directory paths, or box names with a digit suffix. CI greps for them and fails.

## Keep this file current

When you hit a problem that cost you a retry, or a gate or CI failure you did not expect, add a short note in the nearest `CLAUDE.md`: the repo root for repo-wide traps, `crates/<name>/CLAUDE.md` for a crate-specific one. Write the symptom, the cause, and the fix in two or three lines. Add to an existing item instead of duplicating it. Remove a note once the code makes it impossible to hit.
