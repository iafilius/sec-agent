## 1. Fix `sec open` contradictory success/failure banner

- [x] 1.1 In `handleOpen` (cmd/sec-agent/main.go), track which profiles actually unlocked (e.g. a slice/counter of successes) instead of only tracking `lastToken`
- [x] 1.2 Gate the "Session unlocked successfully" banner and `export SEC_SESSION_TOKEN=...` output on at least one profile having succeeded; skip both when zero profiles succeeded
- [x] 1.3 Exit non-zero when every requested profile failed to unlock; exit zero when at least one succeeded, and verify via a test that covers both outcomes
- [x] 1.4 Add a test reproducing the confirmed report: a profile whose `InitializeMasterKey`/keychain step fails must not be followed by a success banner or non-empty exported token
- [x] 1.5 Verify the existing multi-profile success path (workspace-linked profile + active profile both succeeding) still prints the "✨ Unlocked profile..." message and the success banner unchanged

## 2. Fix `sec status --all --json`

- [x] 2.1 In `handleStatusAll` (cmd/sec-agent/cmd_diagnostics.go), build a JSON-serializable struct from the same `profileInfos`/namespace data already computed, and marshal+print it to stdout when `jsonErrors` is true, returning before the plain-text table prints
- [x] 2.2 Add a test verifying `sec status --all --json` output parses as valid JSON and includes profile name, tier, session status, stored key count, and expired key count
- [x] 2.3 Verify `sec status --all` without `--json` still prints the existing plain-text table unchanged

## 3. Fix `session recover --help` missing `--profile`

- [x] 3.1 Add `--profile <name>` to the `session` command's `Usage` and `Flags` fields in `cmd/sec-agent/registry.go`
- [x] 3.2 Verify `sec session recover --help` output now lists `--profile`

## 4. Verification

- [x] 4.1 Run the full test suite (`go test ./...`) and confirm all tests pass
- [x] 4.2 Grep existing tests for assertions on `sec open`'s exit code or output to confirm none silently assumed the old always-succeeds behavior; update any that did
