# Tasks

## 1. Baseline on master

- [ ] 1.1 Build the `sec-agent` binary from `fb_backup-v2.19.2-verify` and confirm `sec --version` reports v2.19.2
- [ ] 1.2 Run `sec backup batch list` and `sec backup batch show` against the existing vault (read-only)
- [x] 1.3 Run the backup package tests and record whether `TestStealthBackupRunRealRsyncOverGoSSH` still fails
  - Result: failed with the macOS system rsync (openrsync 2.6.9). Passes after `brew install rsync` (GNU rsync 3.5.2, protocol 33).
- [x] 1.4 Add a preflight warning in `sec backup run` when the local rsync is openrsync, recommending `brew install rsync`

## 2. Migrate the batch definition

- [ ] 2.1 Translate the batch definition into the upstream manifest schema (`src`, `dest`, `excludes`, `sparse`, `backup_dir`, `log_file`, `timeout`). Use generic names in docs and examples
- [ ] 2.2 Keep each folder as its own entry in one batch. Do not merge a separate folder into a parent source. Use a `dest` name that matches its role
- [ ] 2.3 Store `server_alive_interval` and `server_alive_count_max` on the SSH target (or per folder) instead of `ssh_options`
- [ ] 2.4 Record the exact `sec backup add-folder` commands used, in the developer's review notes (no real names in the repo)
- [ ] 2.5 Check that the migration does not leave stale legacy keys (`backup-batch/<name>`) in the vault, or record them as a known manual cleanup step

## 3. Overlap and TCC (documentation only)

- [ ] 3.1 Document in the backup docs (`docs/disaster_recovery_and_backups.md`, and the batch section of `docs/user_guide.md`) that folder sources must not overlap, and that nested sources need an `--exclude` on the outer folder
- [ ] 3.2 Document that macOS TCC-protected paths cause rsync exit 23, and show the generic pattern for excluding them. Do not list concrete paths from a personal machine
- [ ] 3.3 Document the `--tofu` requirement on first run, and the need to pass the same `--profile` to `define` and `run`

## 4. Verification on upstream master

- [ ] 4.1 Run `sec backup batch show <batch>` and compare with the table from 2.1 (`show` does not print per-folder excludes; check them with `--json` or the vault)
- [x] 4.2 Run a dry run of the full batch with explicit user approval. Result: six of seven folders OK; one home-folder source failed with exit 23 (TCC) until excluded. After the fix all seven folders synchronised in one attempt with exit 0
- [x] 4.3 Confirm the 10-minute keepalive and the locked-vault refusal, which are not yet verified end-to-end (see "Verified claims" in design.md). Result: unit tests `TestStealthBackupKeepaliveExtendsSession`, `TestStealthBackupLockedVaultRefusesBeforeStart` and `TestSSHServerAliveMonitorClosesAfterMaxMissedProbes` pass. A live 10-minute refresh was not observed end-to-end
- [ ] 4.4 Confirm the openrsync warning in `sec backup run` on a Mac with only `/usr/bin/rsync` (temporarily), and that no warning appears with GNU rsync
- [ ] 4.5 Check the retry cost: time one attempt against a tree with a TCC-blocked subtree, and decide whether permission errors (exit 23) should stop retrying (see design.md, "Dry-run findings" 3 and 4)
- [ ] 4.6 Check cloud-sync behaviour: does `rsync --dry-run` trigger downloads of cloud-only (`SF_DATALESS`) placeholder files? Verify with `find ... -flags +dataless | wc -l` before and after a dry run. Status: the dry run has not yet completed in a non-interactive session (it needs an interactive BIP39 prompt), so the before/after count is still open
- [x] 4.7 Check whether `sec backup add-folder` arguments reach shell history, and record the result. Result: the zsh history contains no `add-folder` or `batch define` lines, because those commands were run from a non-interactive session and not from the user's shell. Interactive use was not checked

## 5. Review handover for the developer

- [ ] 5.1 Confirm the reproduction steps in `proposal.md` ("Review guide") work on a clean checkout of `fb_backup-v2.19.2-verify`
- [ ] 5.2 Confirm each finding in "Verified claims" and "Dry-run findings" (design.md) has a status: confirmed, failed, or follow-up
- [x] 5.3 Run `openspec validate devtest-backup-v2-19-2-feedback --strict`. Result: valid
- [x] 5.4 Check the docs and this change for real folder, batch, and personal-library names (privacy rule). Only generic examples may remain. Result: a grep for personal names and paths finds no matches after the cloud-folder term was made generic
