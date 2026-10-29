# Credential store and key custody

Status: Proposed 2026-10-29. Not built. Amends ADR-0013 (storage). Refers to ADR-0043 for the credential kinds and shapes this store holds.

Fleet will run Jobs with the user's own agent and forge credentials. The server must keep them between Jobs and hand them to a Box only for the Job that needs them. This ADR fixes where they live, how they are sealed and who holds the key.

## Decision

### Tables

- `credentials`, one row per stored credential: `user_id`, `kind`, `shape`, `ciphertext`, `key_id`, `fingerprint`, `login`, `expires_at`. `kind` and `shape` are defined in ADR-0043. `fingerprint`, `login` and `expires_at` are plaintext display fields and never hold the secret.
- `credential_use`, an insert-only audit table: one row each time a credential is read for a Job. The server role has no `UPDATE` or `DELETE` grant on it.

### Sealing

- Cipher: XChaCha20-Poly1305.
- AAD: `user_id|credential_id|kind`. A ciphertext copied to another row, user or kind fails to open.
- Key ring: a set of master keys selected by `key_id`. New writes use the current key. A row opens with the key its `key_id` names, so rotation needs no downtime and re-sealing runs as a background pass.

### Master key

- The master key is a file mounted into the server pod from a Kubernetes Secret. external-secrets syncs the Secret and a secret generator creates it. The user chose no heavy hardening for now.
- Sealing goes through a `Sealer` trait. `FileSealer` is the first implementation. A KMS or Vault Transit backend can replace it later without a schema change.

### Protection and its limit

This design protects DB backups and read-only SQL, not a compromised server pod.

The key and the plaintext coexist in the server pod while a Job is claimed. Anyone who runs code in that pod can read both.

## Consequences

- A stolen database dump or a read-only SQL account yields ciphertext only.
- etcd encryption at rest is the operator's concern. Without it the Kubernetes Secret holding the master key sits in etcd in the clear.
- A secret generator that regenerates the key on refresh would make every stored credential unreadable. Before this ships, the infra task CRED-70 must verify the `creationPolicy` and `refreshInterval` of the external-secrets object and the generator, so the key is created once and kept.
- Losing the master key loses every credential. The user re-enters them. No recovery path exists.
- The audit table records reads. It cannot stop a read by a compromised pod.

## Considered and rejected

- **KMS now.** Adds an availability dependency on the job claim path: a KMS outage would stop every Job from starting. `Sealer` keeps the option open.
- **pgcrypto.** The key would appear in SQL text, in query logs and in `pg_stat_statements`, which puts it beside the data it protects.
- **A key in an environment variable.** It shows in `/proc`, in crash dumps and in pod specs, and it cannot hold a ring of keys cleanly.

## Amendment to ADR-0013 (storage)

Postgres also holds `credentials` and `credential_use`, defined above. The rule "prompts are sensitive data at rest" extends to credentials, with the sealing and key custody set here.
