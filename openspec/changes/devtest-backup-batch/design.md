# Design

## Context

The existing backup command runs one job per invocation and has no sequencing, retry, or session keepalive. The vault session has a fixed TTL set by `sec extend`, which does not cover a long batch. See proposal.md - Why.

## Goals / Non-Goals

**Goals:**
- Store a batch as one encrypted vault entry, with ordered job entries as structured fields.
- Resolve dates and shared settings once per batch run.
- Retry each job independently, with exponential backoff capped at 30 minutes.

**Non-Goals:**
- Unattended or scheduled runs. Runs are started manually.
- Raw shell command entries. Jobs are structured, and the rsync arguments are built by sec-agent.
- Changes to the single-job `sec backup run` behaviour.

## Decisions

- **Structured job entries, not raw commands.** Each job holds name, source, destination, excludes, and an explicit backup directory. sec-agent builds the rsync arguments. This keeps source paths anchored and avoids shell expansion of `~`. Alternative: raw commands, rejected because they are hard to validate.
- **Transport is rsync over plain `ssh`** (`-e ssh`), as in the original job commands. The batch does not use the sec-agent SSH transport. Host keys are verified by the system `ssh` configuration (`known_hosts`).
- **Optional SSH password from the vault (`ssh_password_key`).** The batch may name a vault path holding the SSH password. The runner reads it through the daemon with no trace, then passes it to `ssh` with `SSH_ASKPASS` and `SSH_ASKPASS_REQUIRE=force`. The askpass helper is a script in a private temp directory, mode 0700. It echoes the `SEC_BATCH_SSH_PASSWORD` environment variable, so the password never appears in argv or on disk. The temp directory is removed when the batch ends. Trade-off: the password sits in the rsync child process environment, which same-user processes can read. Key auth from the vault (`ssh_key_key`) is planned as a follow-up.
- **Explicit backup directory per job.** Each job sets its own `--backup-dir` and log file path. No history path is derived from the folder name. The batch is stored under the `backup-batch/<name>` vault key, which keeps it out of `sec backup jobs`. `max_attempts` defaults to 5 and is set per batch.
- **Retry policy:** 5 attempts per job. Waits double from 5 seconds, capped at 30 minutes. Alternative: fixed interval, rejected because it retries too often during long outages.
- **Continue on failure.** A job that exhausts its attempts is recorded, and the batch moves on. The batch exits non-zero if any job failed.
- **Client-side keepalive every 10 minutes.** The batch runner sends an authenticated `status` request to the daemon every 10 minutes. This refreshes the sliding grace window (default 30 minutes). If the hard session TTL is near its end, the runner extends the session. Alternative: a long `sec extend` TTL, rejected because it widens the exposure window for all commands.
- **Batch hidden from public output.** Batch listings show only the batch name and job count, not job details.

## Risks / Trade-offs

- [Partial rsync transfers on retry] → `--partial-dir` and `-b` let a re-run resume and keep overwritten files.
- [Session expires mid-batch if keepalive fails] → The batch fails the current job and reports the session error, rather than continuing unlocked.
- [Password in the rsync process environment] → Same-user processes can read it. Only the vault path is stored in the batch, never the password.
- [Plain ssh bypasses sec-agent host-key pinning] → The system `ssh` strict host-key checking applies. A host missing from `known_hosts` fails the job without retry.

## Migration Plan

Add the batch entry type to the vault. No existing data is migrated. Rollback removes the batch entry, and single-job backups continue to work unchanged.

## Open Questions

None. Resolved: the sliding grace window (default 30 minutes) is refreshed by authenticated requests, and the hard session TTL defaults to 8 hours.
