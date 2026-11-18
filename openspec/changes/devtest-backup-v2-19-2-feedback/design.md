# Design

## Context

Branch `fb_backup-batch` built a second batch engine (`cmd_backup_batch.go`, `backup-batch/<name>` vault keys, `ssh_options`), while upstream v2.19.2 ships `sec backup batch` on `backup/<name>` manifests. Testing showed:

- The local engine calls `rsync -e "ssh <ssh_options>"` directly, bypassing `sec ssh-stdio`.
- Upstream has no check that folder sources overlap. A home-folder source (`~/`) contains several other sources, so overlap is only avoided by hand-written `--exclude` lists.
- The upstream test `TestStealthBackupRunRealRsyncOverGoSSH` failed on macOS. Root cause: `findLocalRsyncBinary` (around line 1634 of `cmd_backup.go`) checks `/opt/homebrew/bin/rsync`, then `/usr/local/bin/rsync`, then `PATH`. Without Homebrew rsync it falls back to `/usr/bin/rsync`, which is openrsync 2.6.9 (protocol 29). Its `--server` mode does not write the remote `--log-file`. With GNU rsync 3.5.2 (protocol 33) the test passes. This was confirmed by installing GNU rsync, not only inferred.

## Goals / Non-Goals

**Goals**
- One batch engine (upstream), validated on a branch from `origin/master`.
- Express a multi-folder batch definition in the upstream manifest schema (generic example names in docs).
- Make overlap between folder sources a detected error, not a silent double transfer.

**Non-Goals**
- Changing rsync transport, retry algorithm, or keepalive behavior in upstream.
- Pushing or merging the archive branch `fb_backup-batch-archive`.
- Running a real backup without explicit approval.

## Decisions

1. **Use upstream batch and drop local engine.** Upstream already covers retry, keepalive, timeouts, sparse, and excludes, and uses the stealth transport. Keeping both means two sources of truth for the same vault data.
2. **Replace `ssh_options` with vault keys.** Use `server_alive_interval` and `server_alive_count_max` per SSH target (or per job or folder), as upstream does. This removes the raw SSH option string that the stealth transport was meant to hide.
3. **Overlap is a documented rule, not a code check.** Upstream has no overlap validation and this change does not add one. Users avoid overlap by adding `--exclude` on the outer folder. Documentation is the chosen mechanism.
4. **Untrack OpenSpec skill copies.** Already gitignored (`.gitignore` on master); tracked copies are removed with `git rm --cached` so they are regenerated locally only.

## Verified claims (handover v2.19.2 vs. code on `fb_backup-v2.19.2-verify`)

| Claim in handover | Status | Evidence |
|---|---|---|
| `sec backup batch define|list|show|run` uses the stealth transport | Confirmed in code | `cmd_backup.go` `-e "<sec> ssh-stdio"` (around line 1290) |
| Accepts `folders`/`src` or `jobs`/`source` schemas | Confirmed in code | `backup_manifest.go` lines 92–93 and 335–336 |
| `{date}` and `{datetime}` placeholders | Confirmed in code | `backup_manifest.go` lines 264–265 |
| Per-folder retry, exponential backoff, cap 30m | Confirmed in code | `max_attempts` in `backup_manifest.go` line 330; tests in `cmd_backup_test.go` |
| Continues after a failed folder, exits 1 | Confirmed in code | `TestBackupBackoffDoublesAndCaps` and batch tests |
| Automatic 10m session keepalive, refuses on locked vault | Code present, not yet verified end-to-end | `cmd_backup.go` line 39; needs a run with a locked vault (task 4.x) |
| Per-folder `--sparse`, `--timeout`, `--server-alive-*` in vault | Confirmed in code | `cmd_backup.go` `add-folder` around lines 529–612 |
| AppleDouble `._*` always excluded | Confirmed in code | `backup_manifest.go` lines 26–44 and 306–315 |
| No overlap check between folder sources | Confirmed: none exists | `grep -i overlap` over `cmd/` and `internal/store/` returns nothing |
| Runs reliably with the system rsync | Not confirmed; fails with openrsync | Test failure, see Context; passes with GNU rsync 3.5.2 |
| Batch run completes all folders | Partly confirmed: six of seven sources OK in a dry run; one home-folder source fails with exit 23 (TCC) until excluded | Dry-run findings below |

## Dry-run findings (GNU rsync 3.5.2, upstream `sec backup batch run --dry-run`)

1. **TCC-protected paths cause exit 23.** A terminal process cannot read some macOS-protected `~/Library` subtrees (opendir "Operation not permitted"). rsync reports exit 23 for the whole folder. Fix used: per-folder `--exclude` on the home-folder source. Docs must describe the pattern, not the concrete list.
2. **Iterative exclude discovery.** Each dry run exposed one more blocked subtree. The fix is found by reading the rsync error output, not by any upstream feature.
3. **Exit 23 is retried although it is not transient.** Permission errors do not clear between attempts, so `max_attempts` (default 5, backoff 5s to 40s) only repeats the same failure.
4. **Full re-walk per attempt.** Each attempt walks the whole tree again. With a large, blocked tree, one attempt took roughly 15 to 20 minutes. Five attempts make a failing folder very slow.
   - Feedback candidate: treat permission errors as non-retryable, or report them once and continue, and skip folders that already failed for a permanent reason.
5. **Overlap risk is real.** A home-folder source that contains other sources must exclude them, otherwise files are transferred twice. This is a documentation rule (decision 3).
6. **Host key.** The NAS host key is not known the first time. Without `--tofu` the run waits at an interactive prompt. Docs must say this.
7. **Profile.** `batch run` must use the same vault profile as `batch define`. Otherwise it fails with "vault profile is locked". Docs must say this.
8. **Legacy manifest keys.** Manifests from the archive branch may carry keys that upstream does not read (for example `rsync_timeout` and `ssh_options`). Upstream silently ignores these (not verified end-to-end). Migration must write the upstream keys.
9. **Privacy.** Terminal output of a real run shows real folder paths. That is acceptable on the user's own terminal. Docs, specs, and commits must use generic examples only.

## Risks / Trade-offs

- Overlap is not enforced. A mistyped exclude can cause a double transfer or a missed folder. Mitigation: the review step in tasks 3.2 and 4.1 checks the batch definition by hand.
- Migrating the vault from `backup-batch/<name>` to `backup/<name>` is a one-time change. The migration is a separate, approved step; until then the archive branch keeps the old data.
- The openrsync warning depends on `rsync --version` output. If Apple changes that output, detection breaks silently; the unit test uses fake scripts and does not cover that.
- GNU rsync (`brew install rsync`) is the recommended local rsync for `sec backup`. openrsync stays usable but triggers the warning.
