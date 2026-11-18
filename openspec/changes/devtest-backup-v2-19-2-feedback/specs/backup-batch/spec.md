# Spec Delta

## Purpose

Defines how `sec backup batch` runs a named set of folder backups to one remote target over the zero-trace stealth transport, so that a multi-folder backup is resilient, non-overlapping, and configured from the encrypted vault.

## ADDED Requirements

### Requirement: Single batch engine
The system SHALL execute named folder batches only through `sec backup batch <define|list|show|run>` and its stored manifest. A parallel batch engine MUST NOT be used.

#### Scenario: Batch run uses the stored manifest
- **WHEN** the user runs `sec backup batch run example-batch`
- **THEN** the system loads the manifest stored under the `backup/example-batch` vault key and backs up each folder in it

### Requirement: Stealth transport
The system SHALL run rsync through `sec ssh-stdio` so that folder names, remote volume paths, usernames, and SSH options do not appear in shell history, process arguments, or the audit log.

#### Scenario: No SSH options in process arguments
- **WHEN** a batch folder is backed up
- **THEN** the rsync process arguments contain `-e "<sec> ssh-stdio"` and no `-o` SSH option strings

### Requirement: Non-overlapping folder sources
The batch definition SHOULD have source folders that do not overlap, so that every file is backed up by exactly one folder. The system does not validate this in code. Operators avoid overlap by adding `--exclude` on the outer folder, and the documentation MUST describe this rule.

#### Scenario: Outer folder excludes the nested source
- **WHEN** a batch contains `~/` with `dest` `example-home` and `~/Example` with `dest` `example-media`
- **THEN** the `example-home` excludes include `Example` so that no file is transferred by both jobs

#### Scenario: Overlap is documented
- **WHEN** a user reads the backup batch documentation
- **THEN** it explains that nested sources must be excluded from the outer folder

### Requirement: macOS privacy-protected paths
The system SHALL document that rsync exit code 23 with "Operation not permitted" on a folder means macOS TCC blocked a path, and that the fix is a per-folder `--exclude` for that path. The documentation MUST show this as a generic pattern and MUST NOT list personal paths.

#### Scenario: TCC block is excluded
- **WHEN** a folder fails with exit 23 and "Operation not permitted" on a subpath of a protected location
- **THEN** the operator adds an `--exclude` for that subpath to the folder and reruns the batch, and the folder completes with exit 0

### Requirement: No private backup inventory in project artifacts
Documentation, specs, examples, and commits in this repository SHALL NOT name the real folders, batch names, or personal library bundles that a user backs up or excludes. Examples MUST use generic names such as `example-batch`, `example-home`, and `example-media`.

#### Scenario: Review check before commit
- **WHEN** an author prepares a change for review
- **THEN** they search the diff for the real folder and batch names and remove any match before committing

### Requirement: Vault-driven timeouts and keepalive
The system SHALL read `timeout`, `server_alive_interval`, and `server_alive_count_max` from the vault per folder, per job, or per SSH target, and MUST NOT use hardcoded values in code for these settings.

#### Scenario: Per-folder timeout overrides the job default
- **WHEN** a folder defines `timeout` of 600 and the job defines `timeout` of 300
- **THEN** rsync is started with `--timeout=600` for that folder

### Requirement: Per-folder retry and continuation
The system SHALL retry a failing folder with exponential backoff up to `max_attempts`, continue with the remaining folders when one exhausts its attempts, and exit non-zero after printing a summary.

#### Scenario: Failing folder does not stop the batch
- **WHEN** the `example-home` folder fails all attempts with exit code 23
- **THEN** the remaining folders are still backed up and the batch exits with code 1 after printing the summary

#### Scenario: Backoff doubles and is capped
- **WHEN** a folder fails repeatedly with the default `max_attempts` of 5
- **THEN** the wait between attempts starts at 5 seconds, doubles each time, and never exceeds 30 minutes

#### Scenario: Retry cost is reported
- **WHEN** a folder fails with a permission error (exit 23) and is retried
- **THEN** each attempt re-walks the full tree, so the total time is recorded as a feedback item; the retry policy itself is unchanged in this change

### Requirement: Batch definition schema
The system SHALL accept batch definitions with either `folders` (entries using `src`) or `jobs` (entries using `source`), and SHALL expand `{date}` and `{datetime}` placeholders in `backup_dir` and `log_file`.

#### Scenario: Legacy jobs schema is accepted
- **WHEN** a batch file uses `"jobs"` with `"source"` entries
- **THEN** `sec backup batch define` stores the entries as folders with the same sources

#### Scenario: Derived history path and log file
- **WHEN** a folder has a `dest` and no `backup_dir` or `log_file`
- **THEN** the system derives `<Prefix>-History/<YYYY-MM-DD>` and `rsync_<slug>_<YYYY-MM-DD_HHMM>.log` under the remote base

### Requirement: Mandatory macOS exclusions
The system SHALL always exclude `.DS_Store`, `.Trash*`, and AppleDouble files (`._*`) from every folder, in addition to the configured excludes.

#### Scenario: AppleDouble files are not transferred
- **WHEN** a folder with source `~/example-media` is backed up
- **THEN** rsync receives `._*` through `--exclude-from=/dev/fd/3` and no `._*` file is written to the remote

### Requirement: Local rsync preflight
The system SHALL warn, without failing, when the local rsync binary is openrsync, and SHALL recommend installing GNU rsync with `brew install rsync`.

#### Scenario: Openrsync triggers a warning
- **WHEN** `sec backup run` resolves `/usr/bin/rsync` and `rsync --version` reports openrsync
- **THEN** a warning is printed to stderr and the run continues

#### Scenario: GNU rsync is silent
- **WHEN** the resolved rsync reports GNU rsync (for example `/opt/homebrew/bin/rsync` 3.5.2)
- **THEN** no openrsync warning is printed

### Requirement: Session keepalive during long batches
The system SHALL refresh the vault session in the background every 10 minutes while a batch runs, extending the session when its remaining TTL is under 30 minutes, and SHALL refuse to start if the vault is locked.

#### Scenario: Locked vault stops the batch before the first folder
- **WHEN** `sec backup batch run` starts while the vault is locked
- **THEN** the command fails before any rsync process is started

### Requirement: Per-folder options from the vault
The system SHALL accept `--sparse`, `--timeout`, `--server-alive-interval`, `--server-alive-count-max`, `--backup-dir`, `--log-file`, and `--exclude` on `sec backup add-folder`, and store them in the encrypted manifest.

#### Scenario: Folder options are stored and shown
- **WHEN** the user runs `sec backup add-folder example-batch "~/" --dest example-home --timeout 600 --exclude Example`
- **THEN** the encrypted manifest stores the folder with `timeout` 600 and the `Example` exclude; `sec backup batch show example-batch` lists the folder, and the per-folder excludes are checked with `--json` or the vault, because `show` does not print them
