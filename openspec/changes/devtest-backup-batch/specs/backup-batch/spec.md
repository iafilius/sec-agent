# Backup Batch

## ADDED Requirements

### Requirement: Named batch definition in the vault
The system SHALL store a named backup batch as an encrypted entry in the vault. A batch SHALL contain an ordered list of backup jobs and its retry settings. The batch definition SHALL NOT be shown in public listings or output.

#### Scenario: Batch stored encrypted
- **WHEN** a batch is created or updated
- **THEN** its definition is written to the vault in encrypted form

#### Scenario: Batch hidden from listings
- **WHEN** the user lists backup jobs or batches without an unlocked vault
- **THEN** the batch's jobs, paths, and hosts are not displayed

### Requirement: Ordered batch run
The system SHALL run a named batch by executing its jobs in the defined order, when started manually with the vault unlocked.

#### Scenario: Jobs run in order
- **WHEN** a batch with jobs A, B, C is run
- **THEN** job A starts before job B, and job B before job C

#### Scenario: Locked vault
- **WHEN** a batch is run and the vault is locked
- **THEN** the run fails before any job starts, and no job is executed

### Requirement: Per-job retry with backoff
The system SHALL retry a failed job up to 5 attempts in total. The wait before each retry SHALL double after each failure, and each wait SHALL NOT exceed 30 minutes.

#### Scenario: Transient failure recovers
- **WHEN** a job fails on attempt 1 and succeeds on attempt 2
- **THEN** the job is recorded as succeeded and no further attempts are made

#### Scenario: Backoff grows and is capped
- **WHEN** a job keeps failing
- **THEN** each wait is double the previous wait, and no wait exceeds 30 minutes

### Requirement: Continue after a failed job
The system SHALL continue the batch with the next job when a job still fails after its final attempt. The system SHALL record the result of each job.

#### Scenario: Failed job does not stop the batch
- **WHEN** job B fails all 5 attempts and job C is defined after it
- **THEN** job B is recorded as failed and job C still runs

### Requirement: Batch exit status
The system SHALL exit with a non-zero status when any job in the batch failed, and zero when all jobs succeeded.

#### Scenario: All jobs succeed
- **WHEN** every job in the batch succeeds
- **THEN** the batch exits with status zero

#### Scenario: Any job fails
- **WHEN** at least one job failed after all attempts
- **THEN** the batch exits with a non-zero status

### Requirement: Internal session keepalive
The system SHALL keep the vault session valid for the full duration of a running batch without requiring user action.

#### Scenario: Long batch completes
- **WHEN** a batch runs longer than the default session lifetime
- **THEN** the session remains valid until the batch finishes, with no user action required

### Requirement: Optional SSH password from the vault
The system SHALL allow a batch to name a vault path holding the SSH password for its rsync transport. The password SHALL be passed to `ssh` through `SSH_ASKPASS` and SHALL NOT appear in command arguments, the batch definition, or logs.

#### Scenario: Password read from the vault
- **WHEN** a batch sets `ssh_password_key` and the vault is unlocked
- **THEN** the runner reads the password from that path and supplies it to `ssh` without printing it

#### Scenario: Missing password
- **WHEN** `ssh_password_key` names a path that is empty or missing
- **THEN** the batch fails before any job runs, with an error that names the path and not the value

