# Proposal

## Why

An earlier branch, `fb_backup-batch`, added its own batch engine (`cmd_backup_batch.go`) in parallel with the batch support that upstream v2.19.2 already ships. That engine duplicated functionality, did not use the zero-trace stealth transport, and had overlap risks in folder excludes. We need to validate the upstream v2.19.2 batch flow on a fresh branch from `origin/master`, and record the remaining feedback.

A dry run of the upstream flow on a real multi-folder batch (macOS, GNU rsync 3.5.2 installed) showed that six of seven sources synchronise cleanly. The seventh, a home-folder source, fails with rsync exit 23 because macOS privacy protection (TCC) blocks several `~/Library` subtrees for the terminal process. Fixing this needs per-folder excludes, which is a documented workaround and not a code change. Two further gaps came up: the retry loop re-walks the whole tree on every attempt, and exit 23 is retried even when the cause is a permission error that will not clear.

## What Changes

- Drop the local batch engine from `fb_backup-batch` in favor of upstream `sec backup batch define|list|show|run`.
- Express a multi-folder batch definition in the upstream manifest schema, using `src`, `dest`, `excludes`, `sparse`, `backup_dir`, `log_file`, and `timeout`. Examples in this change use generic names (`example-batch`, `example-home`, `example-media`).
- Document that folder sources within a batch must not overlap, and that nested sources (for example `~/` and `~/example-media`) are kept apart by an `--exclude` on the outer folder. No code check is added; this is a documented rule.
- Document that macOS TCC-protected paths (for example `~/Library` subtrees that a terminal process cannot read) must be excluded from the home-folder source. The concrete list is per-machine and is not part of the docs.
- Record the retry-cost and exit-23 behaviour as feedback for the developer (see design.md, "Dry-run findings"). The retry algorithm is not changed by this change.
- Replace the per-job `ssh_options` string with vault-stored `server_alive_interval` and `server_alive_count_max` per SSH target, as upstream already supports.
- Stop tracking generated OpenSpec skill copies in git (`.agents/skills/openspec-*`, `.github/skills/openspec-*`). Already applied on branch `fb_backup-v2.19.2-verify`.
- Keep the old branch as `fb_backup-batch-archive` for reference. It is not pushed.

## Capabilities

### New Capabilities

- `backup-batch`: Running a named set of folder backups to a remote target over the stealth transport, with per-folder retry, keepalive, and non-overlapping sources.

### Modified Capabilities

(none; `openspec/specs/` is empty on master)

## Impact

- `cmd/sec-agent/cmd_backup.go` (upstream batch flow, validated and not changed unless a defect is found)
- `internal/store/backup_manifest.go` (manifest schema; the `ssh_options` field is not added)
- `cmd/sec-agent/cmd_backup_batch.go` and `internal/store/backup_batch.go` (only on the archive branch; not carried forward)
- Vault entries `backup-batch/<name>` (replaced by upstream `backup/<name>` manifests; migration is a separate, approved step)
- `.gitignore` and tracked OpenSpec skill files (already done)

## Out of scope

- The handover item "Single-Line + 4-Column Recovery Mnemonic Display Parity" (`sec migrate-v2`, `sec enroll-recovery`, `sec session rotate-seed`, `sec profile new`). It concerns recovery display, not backups, and needs its own change.
- The unrelated vault mnemonic proposal attached to the session (`file_proposal.md`). It is not part of this change.
- Changing the retry algorithm (exit 23 retry policy, full re-walk per attempt). Raised as feedback only.
- Pushing or merging `fb_backup-batch-archive`.
- Running a real backup or writing the live vault without explicit approval.

## Review guide for the developer

Branch: `fb_backup-v2.19.2-verify`, based on `origin/master` (183dbe9), with commit `8370ff3` (untracking OpenSpec skills) and uncommitted changes to `cmd/sec-agent/cmd_backup.go` and `cmd/sec-agent/cmd_backup_test.go`.

Reproduce:

1. `go build -o /tmp/sec-verify ./cmd/sec-agent`, then check `/tmp/sec-verify --version` shows v2.19.2.
2. Install GNU rsync: `brew install rsync`. Confirm `/opt/homebrew/bin/rsync --version` reports 3.x.
3. `go test ./cmd/sec-agent/ ./internal/store/ -run 'Backup|Batch|Stealth|Rsync'` should pass. `TestStealthBackupRunRealRsyncOverGoSSH` fails with openrsync and passes with GNU rsync.

Files to review:

- `cmd/sec-agent/cmd_backup.go`: `rsyncIsOpenrsync` and `findLocalRsyncBinary` (around line 1634), the openrsync warning in the run path (around line 1858), and the remote command with `--log-file` (around line 1166).
- `cmd/sec-agent/cmd_backup_test.go`: `TestRsyncIsOpenrsyncDetection` and `TestStealthBackupRunRealRsyncOverGoSSH`.
- `internal/store/backup_manifest.go`: manifest schema, `EffectiveExcludes` and AppleDouble handling, `DeriveRemoteLogPath`.

Acceptance criteria:

- The backup, batch, stealth, and rsync tests pass on macOS with GNU rsync installed.
- With openrsync as the only rsync, `sec backup run` prints the warning and still runs.
- A multi-folder example batch can be defined, shown, and dry-run to exit 0 on a Mac with GNU rsync, and no two sources overlap once the documented excludes are applied.
- The docs and this change contain no real folder, batch, or personal-library names. Only generic examples are used.
- Every finding in `design.md` under "Verified claims" is confirmed or has a filed follow-up.
