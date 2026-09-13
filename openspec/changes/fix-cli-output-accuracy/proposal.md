## Why

Live testing on v2.13.1-dev1 (from another workspace, using only a
throwaway test profile and a fake value) surfaced three CLI output-accuracy
bugs, the first of which is a Tier 0 finding that is now confirmed
systemic. `sec open`'s original "contradictory ACCESS DENIED + success
banner" bug (already fixed at its root cause for the hijack-detector case
in `fix-hijack-detector-false-positive`) has now reproduced under a
**completely unrelated failure mode** — a corrupted/invalidated Keychain
entry for the `test-prof` profile printed `Authentication failed for
profile "test-prof": master key missing or invalidated...` immediately
followed by `Session unlocked successfully. Cache active.` for the same
attempt, and both `set`/`get` against that "successfully unlocked" profile
then failed with `Session locked or expired`. This proves the bug is not
specific to the hijack detector: `handleOpen` in `cmd/sec-agent/main.go`
loops over profiles, `continue`s past any per-profile failure, and then
unconditionally prints the success banner after the loop regardless of
whether any profile actually unlocked. Two smaller, previously-reported
output-accuracy gaps remain open and are grounded in source in this same
pass: `sec status --all --json` silently ignores `--json` and always
prints the plain-text table, and `sec session recover --help` never lists
`--profile`, even though the tool's own runtime remediation text tells
users to pass it.

## What Changes

- `sec open` tracks per-profile unlock success/failure and only prints the
  "Session unlocked successfully" banner when at least one profile
  actually unlocked; if every requested profile failed, it prints only the
  failure(s) and exits non-zero, with no contradictory success banner.
- `sec status --all --json` emits actual machine-readable JSON (profiles,
  tiers, session status, key counts, expiring-secret warnings) when
  `--json` is passed, instead of silently printing the plain-text table.
- `sec session recover --help` lists `--profile <name>` in its usage/flags
  output, matching the flag the tool's own runtime remediation text already
  tells users to pass.
- **BREAKING**: scripts that only check `sec open`'s exit code today (which
  currently always exits 0 regardless of per-profile failures, as long as
  no earlier flag/duration validation error occurred) will start seeing a
  non-zero exit code when every requested profile fails to unlock.

## Capabilities

### New Capabilities
- `session-unlock-reporting`: correctness contract for `sec open`'s
  per-profile success/failure reporting and exit behavior.
- `status-json-output`: contract for `sec status --all --json` actually
  emitting structured JSON matching the requested format.

### Modified Capabilities
(none — the `session recover --help` fix is a documentation/usage-text
correction with no spec-level behavior change, tracked as a task only)

## Impact

- `cmd/sec-agent/main.go` (`handleOpen`)
- `cmd/sec-agent/cmd_diagnostics.go` (`handleStatusAll`)
- `cmd/sec-agent/registry.go` (`session` command `Usage`/`Flags`)
- Existing tests exercising `sec open` exit codes and `sec status --all`
  output (survey during implementation; extend rather than replace)
