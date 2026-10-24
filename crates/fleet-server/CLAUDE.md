# fleet-server traps

- **Migration numbers.** Check `ls crates/fleet-server/migrations` for the next free number before naming a file. A task title can name a number that is taken, and sqlx refuses duplicate versions.
- **Dynamic SQL.** sqlx 0.9 `query` takes only `&'static str`. `format!` into a query fails with E0277. Write each statement as a full `const` literal.
- **Job ids and idempotency.** `job_id` is `EventId::generate()` (ULID shape), generated in Rust and bound as a parameter. A repeat `submit_job` with the same key and identical prompt, repo, base ref and `open_pr` returns the stored job. Different parameters give `StoreError::KeyConflict`, which the handler maps to gRPC `ALREADY_EXISTS` with a fixed message.
