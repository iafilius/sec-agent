## Context

`handleOpen` in [main.go#L425-L545](../../../cmd/sec-agent/main.go) loops
over `openProfiles`, and on any per-profile failure (`InitializeMasterKey`
error, daemon IPC error, or `resp.Success == false`) it prints an error and
`continue`s — but never tracks whether *any* profile actually succeeded.
After the loop, it unconditionally prints "Session unlocked successfully...
Cache active." and exports `SEC_SESSION_TOKEN=<lastToken>` (empty string if
every profile failed). This is confirmed, via live re-test on v2.13.1-dev1,
to reproduce under an unrelated failure mode (a corrupted Keychain entry),
not just the already-fixed hijack false-positive — see proposal.md - Why.
`handleStatusAll` in `cmd_diagnostics.go` has no JSON branch at all; every
`fmt.Println`/`fmt.Printf` call is unconditional plain text, so the global
`jsonErrors` flag (checked elsewhere in the codebase, e.g.
`handleStatusQuick`) is simply never consulted here. The `session` command
entry in `registry.go` has `Usage: "sec session recover"` with no `Flags`
field, while `handleSessionRecover`'s own interactive-blocker remediation
text already tells users to pass `--profile <name>`.

## Goals / Non-Goals

**Goals:**
- Make `sec open`'s output and exit code agree with the true per-profile
  outcome, for any failure cause — not just the hijack-detector case
  already fixed.
- Make `sec status --all --json` emit real JSON.
- Make `sec session recover --help` list the flag its own runtime
  remediation text already recommends.

**Non-Goals:**
- Not redesigning `sec open`'s multi-profile UX beyond accurate
  success/failure reporting (e.g. not changing the "1 Touch ID prompt"
  messaging, which already only fires when `len(openProfiles) > 1`).
- Not changing `sec status --all`'s plain-text table format or content —
  only adding a JSON emission path alongside it.
- Not adding new flags to `session recover` — only documenting the
  existing (already-functional) `--profile` flag in `--help` output.

## Decisions

**Track per-profile success in `handleOpen` with a simple counter/slice
of successful profiles, and gate both the success banner and the process
exit code on it being non-empty.** This directly targets the confirmed
root cause (unconditional post-loop banner print) with the smallest
possible change — no restructuring of the per-profile loop itself, no new
flags, no behavior change for the all-succeed or all-fail-with-one-profile
cases users already rely on.

**For `sec status --all --json`, build the same `profileInfos` /
namespace data the plain-text path already computes into a struct, and
marshal it to JSON when `jsonErrors` is true, returning before the
plain-text printing begins.** Reuses the existing data-gathering logic
(profile discovery, per-profile daemon status queries, namespace
aggregation) rather than duplicating it — only the output stage branches.

**For `session recover --help`, add `--profile <name>` to the `Usage` and
`Flags` fields on the `session` command's registry entry.** This is a
metadata-only change (the flag is already parsed and functional at
runtime; only the registry's declared `Usage`/`Flags` are out of sync).

## Risks / Trade-offs

[Gating `sec open`'s exit code on real success is a **BREAKING** change
per the proposal — any script relying on `sec open`'s current
always-succeeds-if-flags-valid exit code will start seeing failures
surfaced correctly] → Intended; this is the fix. The proposal's Impact
section calls out surveying existing tests that assert on `sec open` exit
codes, so any such assumption is caught during implementation rather than
discovered later.

[Building a JSON representation of `sec status --all` alongside the
existing plain-text path risks the two views drifting out of sync over
time] → Mitigated by deriving both from the same underlying
`profileInfos`/namespace data already computed once per invocation, so a
future field addition to one is naturally visible when touching the
shared computation.

## Migration Plan

- Ship as a normal point release; no data or vault format changes.
- Document the `sec open` exit-code change in the changelog as breaking,
  per the proposal, so any consuming script can be updated.
- No other user action required.
