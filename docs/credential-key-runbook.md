# Credential key rotation, backup and restore

Operations runbook for the credential master key. Design: [ADR-0040](adr/0040-credential-store-and-key-custody.md). Deployment: [infra/README.md](../infra/README.md), section Master key.

## What exists

- The server reads the key ring from the file named by `FLEET_MASTER_KEY_FILE` once, at startup. In the cluster that file is `/etc/fleet/master-key/keyring`, from Secret `fleet-master-key`.
- The file holds one key per line as `key_id:hex`, with exactly 64 hex digits (32 bytes). A `key_id` uses ASCII letters, digits, `-` and `_`. Blank lines are skipped. A repeated `key_id` or a malformed line stops startup.
- The first line is the active key. New seals use it. Every line can open a row whose `credentials.key_id` names it.
- Each `credentials` row stores `ciphertext` and the `key_id` that sealed it. `fingerprint`, `login` and `expires_at` are plaintext.
- No command re-seals rows. `Sealer::rewrap` exists in `crates/fleet-server/src/cred/seal.rs` and no runtime path calls it yet. ADR-0040 describes a background re-seal pass that is not built.

## Back up

Back up two things, and keep them apart.

1. The database. A `pg_dump` of the fleet database covers `credentials`, `users` and `credential_use`. The dump holds ciphertext, so it is safe to store with ordinary database backups.
2. The key ring file, the whole file with every line. Store it in a different system and under different access than the database dumps. A dump and the key stored together give up every credential, and the ciphertext protects nothing then.

Take a new key backup each time the file changes. A key backup older than the last rotation cannot open rows sealed under the newer key.

## Rotate the master key

1. Back up the current key ring file.
2. Generate 32 random bytes as 64 hex digits, for example `openssl rand -hex 32`. Choose a `key_id` not yet in the file, for example `k2`.
3. Put the new line first and keep every old line below it:

   ```
   k2:<64 hex digits>
   k1:<64 hex digits>
   ```

   Secret `fleet-master-key` is created once (`refreshPolicy: CreatedOnce`, `creationPolicy: Orphan`), so external-secrets never rewrites it. The operator edits the Secret value directly, and `infra/` stays unchanged.
4. Back up the new file.
5. Restart the server pods. The ring loads at startup only, so a running pod keeps the old ring. A bad file stops startup with a message naming the line. During a rolling restart, pods that still hold the old ring cannot open rows sealed under `k2` until the rollout ends. A request that reaches an old pod for such a row fails with `unknown sealing key`. Rows written before the rollout stay readable on every pod.
6. Check which key each row uses:

   ```sql
   SELECT key_id, count(*) FROM credentials GROUP BY key_id;
   ```

New writes now use `k2`. Rows sealed under `k1` still open because `k1` stays in the ring. Do not remove a line while any row names its `key_id`: opening such a row fails with `unknown sealing key`.

Re-sealing old rows has no tool today. A user who stores a credential of the same kind again replaces the row, and the new value seals under the active key. Once the query in step 6 shows no row under `k1`, remove the `k1` line, restart and back up the file. Until then keep `k1`.

## Restore

Restore the database with `pg_restore` or `psql` as usual, then start the server with a key file.

### With the key

Mount the backed-up key ring file at the path in `FLEET_MASTER_KEY_FILE`. Every credential opens: the ring has the key each row names. The restore test `crates/fleet-server/tests/cred_restore.rs` checks this.

### Without the key

The dump alone yields ciphertext only. There is no recovery path (ADR-0040).

- `FLEET_MASTER_KEY_FILE` unset and credential rows present: startup stops with `credentials are stored but FLEET_MASTER_KEY_FILE is not set`.
- A file that is missing, unreadable or malformed: startup stops with a `FLEET_MASTER_KEY_FILE:` message.
- A new file with different keys: the server starts, and nothing signals the mismatch at startup. Any well-formed ring passes, so the first failed open is the first sign. A row sealed under an id the ring lacks fails to open with `unknown sealing key`. A row whose id matches but whose key differs fails with `credential could not be opened`. No `credential_use` row is written for a failed open.

To continue without the old key, users re-enter their credentials. Storing a credential of the same kind replaces the unreadable row. To start the server with no key file, delete the rows first:

```sql
DELETE FROM credentials;
```

`credential_use` keeps its rows after a credential delete (migration 0019), so the audit history survives.

## What happens to credentials

| Situation | Credentials |
| --- | --- |
| Dump plus key | Readable. |
| Dump, key file missing | Server refuses to start while rows exist. |
| Dump, wrong key | Unreadable. Users re-enter them. |
| Key lost, database intact | Unreadable. Same recovery. |
| Rotation with old lines kept | Readable. |
| Rotation with an old line removed too early | Rows under that `key_id` are unreadable. Restore the old line from the key backup. |
