# Proposal

## Why

Backing up several folders to a remote host currently means running separate rsync commands by hand, with no shared ordering, no retry on transient network failures, and no single summary. A named, vault-stored batch lets the operator start one command that runs all jobs in order, retries transient failures, and reports the outcome, while keeping the job definitions private.

## What Changes

- Add a named backup batch that is stored encrypted in the vault and contains an ordered list of backup jobs.
- Add a batch run that executes the jobs in the defined order, started manually after the vault is unlocked.
- Retry each failed job with exponential backoff: 5 attempts, with the wait doubling after each failure and capped at 30 minutes.
- Continue to the next job when a job still fails after its final attempt, record the result, and exit non-zero if any job failed.
- Keep the vault session alive for the duration of the batch internally, so no user action is required.
- Keep batch definitions out of public listings and output.

## Capabilities

### New Capabilities

- `backup-batch`: Running a named, ordered set of backup jobs stored in the vault, with per-job retry and backoff, and an overall result.

### Modified Capabilities

<!-- None. Existing backup job behaviour is reused, not changed. -->

## Impact

- `cmd/sec-agent/cmd_backup.go`: new batch subcommand and run behaviour.
- `internal/store`: encrypted storage of batch definitions in the vault.
- `internal/daemon`: internal session keepalive for the duration of a batch.
- Documentation: operations guide entry for running a batch.
