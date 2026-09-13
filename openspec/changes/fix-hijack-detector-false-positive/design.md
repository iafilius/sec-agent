## Context

`isHijacked` in [internal/daemon/daemon_ipc.go](../../../internal/daemon/daemon_ipc.go)
runs on every IPC connection before the request is parsed. It combines three
signals: a system-wide `pgrep <name>` existence check against
`screensharingd`, `AppleVNCServer`, `remotepairingd`; an `SSH_CLIENT`/`SSH_TTY`/
`SSH_CONNECTION` environment scan of the peer process; and a parent-process
walk looking for an `sshd` ancestor. `remotepairingd` is Apple's
Continuity/RemotePairing daemon and is commonly present continuously on
modern macOS regardless of any active remote session — see proposal.md - Why.
`handleStatusQuick` in `cmd/sec-agent/cmd_diagnostics.go` calls
`queryDaemonRaw` with a ping and only treats a transport-level error as
"daemon not responsive"; it never inspects `resp.Success`, so a hijack-denied
ping reads as healthy.

## Goals / Non-Goals

**Goals:**
- Stop `remotepairingd`'s mere presence from triggering hijack detection.
- Make every hijack denial diagnosable after the fact via the audit log.
- Make `status --quick` agree with every other command about lock state.

**Non-Goals:**
- Redesigning the SSH-ancestry or environment-variable detection paths — no
  reported issue implicates them, and the feedback confirms they consistently
  agree with `status`/`get`/`run`/`audit`.
- Building a general-purpose "explain any security decision" verbose/debug
  flag across the whole CLI — only the hijack-denial path gains explicit
  reason logging.
- Auditing or fixing `status --all --json`'s separate output/JSON-flag bugs —
  out of scope for this change; not part of the Tier 0 blocking issue.

## Decisions

**Drop `remotepairingd` from the process-presence list rather than trying to
make it "connection-aware".** Screen sharing (`screensharingd`,
`AppleVNCServer`) has a meaningful "is a session active" signal available in
principle (an established socket), but `remotepairingd` is a
proximity/pairing negotiation daemon with no stable "actively controlling
this Mac" state to probe — it isn't a remote-control surface at all.
Continue to treat `screensharingd`/`AppleVNCServer` presence as a signal for
now (unchanged from today), since no report demonstrates they misfire, and
scoping their check to an active connection is a larger change not required
to fix the reported blocking issue. Revisit only if a future report shows
the same class of false positive for those two.

**Log the hijack denial reason via the existing `internal/audit` package,
written before the error response is sent.** Keeps a single source of truth
(`audit.log`) for all security-relevant denials instead of introducing a new
log file, matching the existing pattern other daemon operations already use.

**Fix `handleStatusQuick` by checking `pingResp.Success` immediately after
the ping call, alongside the existing transport-error check.** This is a
minimal, localized fix at the exact point identified in the explore-mode
grounding ([main.go](../../../cmd/sec-agent/main.go) `queryDaemonRaw` /
[cmd_diagnostics.go](../../../cmd/sec-agent/cmd_diagnostics.go)
`handleStatusQuick`) rather than changing `queryDaemonRaw`'s error contract,
which other callers already depend on.

## Risks / Trade-offs

[Removing `remotepairingd` could theoretically miss some future
Continuity-based remote-control vector] → Accept for now: no evidence exists
that `remotepairingd` presence ever corresponds to actual remote control: it
has no active-session signal to gate on. Document the removal rationale in
code comments and `docs/design_documentation.md` / `README.md` so it isn't
silently re-added later.

[Audit log entries for hijack denials could themselves leak information about
the vault to someone who can read `audit.log`] → Log only signal type and
matched process name/PID, never secret paths or values (already the case for
every other audit entry).

[This is a **BREAKING** change per the proposal: machines with
`remotepairingd` running will regain access they were previously — and
incorrectly — denied] → Intended; this is the fix. Call it out explicitly in
release notes since operators who worked around the block by other means
should know the underlying gate changed.

## Migration Plan

- Ship as a normal point release; no data migration or vault format change.
- No user action required after upgrading — `remotepairingd` simply stops
  being checked and previously-blocked commands begin succeeding again.
- No rollback concern beyond a normal release rollback: reverting the
  binary restores the previous (broken) behavior.
