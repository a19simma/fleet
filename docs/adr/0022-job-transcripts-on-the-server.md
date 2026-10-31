# Job transcripts on the server

Status: Accepted. Built: the server stores and serves job transcripts, and `fleet logs` reads them. Amends ADR-0013.

ADR-0013 says the server stores prompts and last messages, never transcripts. The goal needs a laptop to read what a Job did, and a Box may be gone by then.

## Decision

The server stores the stream-json output of a Job in Postgres, and `FleetJobs.ReadTranscript` serves it.

- **Table.** `job_transcript` has primary key `(job_id, seq)`, plus `ts_ms` and `chunk` text. A chunk is a batch of stream-json lines of at most 64 KiB.
- **Source.** fleetd sends chunks through `ReportJob` (ADR-0021). The stream-json stdout is the transcript. Claude's session `.jsonl` is not read.
- **Redaction.** fleetd redacts each line with the existing redactor before it leaves the Box.
- **Idempotence.** A repeated `seq` is a no-op.
- **Cap.** 4 MiB per Job, tracked in `jobs.transcript_bytes`. Chunks past the cap are dropped and one `truncated` marker row is written. A Job also holds at most 50,000 transcript rows, each chunk is charged the larger of its text length and 64 bytes against the cap, and one report carries at most 256 chunks. The reply's `acked_through_seq` is the end of the contiguous stored prefix starting at 1.
- **Read.** `ReadTranscript{job_id, after_seq, limit}` returns chunks and `done`. `fleet logs -f` polls it every 1 s.
- **Sensitivity.** The database is treated as sensitive. Transcripts hold prompts, code and shell output. The redactor matches exact values only (ADR-0014), so secrets in other forms can reach the table.
- **Scope.** Only Jobs. The session transcripts that fleetd reads for previews (ADR-0011) still stay on the Box.

## Consequences

- A Job's output outlives its Box and is readable from the laptop.
- Database growth is bounded at 4 MiB per Job. Retention jobs for transcripts are not designed. `jobs` keeps the ADR-0013 retention of one year.
- A leaked client token can read transcripts (ADR-0023).
- A secret in a non-literal form can persist in Postgres, so the care for Box credentials applies to backups of the database.
- The "No transcripts" bullet of ADR-0013 holds only for session transcripts.

## Considered and rejected

- **Final result and the last N chunks only.** Inferred, not part of the design: loses the middle of a failed run, the part a human needs.
- **Object storage.** More infrastructure for a few megabytes per Job.
- **Keep transcripts on the Box and fetch over ssh.** Needs a live Box and a laptop on the VPN, the problem ADR-0015 removes.
