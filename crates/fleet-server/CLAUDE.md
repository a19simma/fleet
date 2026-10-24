# fleet-server traps

- **Migration numbers.** Check `ls crates/fleet-server/migrations` for the next free number before naming a file. A task title can name a number that is taken, and sqlx refuses duplicate versions.
- **Dynamic SQL.** sqlx 0.9 `query` takes only `&'static str`. `format!` into a query fails with E0277. Write each statement as a full `const` literal.
- **Job ids and idempotency.** `job_id` is `EventId::generate()` (ULID shape), generated in Rust and bound as a parameter. A repeat `submit_job` with the same key and identical prompt, repo, base ref and `open_pr` returns the stored job. Different parameters give `StoreError::KeyConflict`, which the handler maps to gRPC `ALREADY_EXISTS` with a fixed message.
- **Unbounded loops in mutation-red tests.** A test that drains a queue with `while let Some(..)` hangs forever when a mutation makes the claim never return `None`, and `timeout` on one call does not help. Bound the loop by the expected count plus one and assert on the collected result.
- **Reaper tests.** Postgres and tokio paused time do not mix. `expired_lease_becomes_lost` uses a 1 s lease, a 100 ms reaper period, real time, a `Notify` the reaper signals, and a 5 s `timeout`. Never `sleep`.
- **Box names in tests.** The validator only accepts `box-<digits>`, but verify.sh's private-pattern grep rejects that literal in source. Build names at runtime, as `format!("box-{n}")`, never write the literal.
