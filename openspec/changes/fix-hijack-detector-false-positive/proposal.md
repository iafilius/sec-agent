## Why

The daemon's remote-session-hijack detector (`isHijacked` in
[internal/daemon/daemon_ipc.go](../../../internal/daemon/daemon_ipc.go)) checks
for the presence of `remotepairingd` anywhere on the host via `pgrep`, alongside
`screensharingd` and `AppleVNCServer`. `remotepairingd` is Apple's general
Continuity/RemotePairing daemon (Watch unlock, Universal Control, AirDrop
proximity, paired-device negotiation) and runs persistently on most modern Macs
whenever any Continuity feature has ever been used — it is not evidence of an
active remote-control or screen-sharing session. Because the check tests
system-wide process *existence* rather than an active *connection*, it fires
on a normal, unremarkable machine state, denies every secret-touching command,
and wipes the in-memory vault cache on the very first IPC connection after
unlock. There is currently no user-facing recovery path (neither Touch ID nor
mnemonic recovery clears it), no audit-log record of the denial reason, and
`status --quick` incorrectly reports the session as healthy while every other
command is denied — because it only checks for a transport error, not
`resp.Success`, so it can't tell a hijack-denied reply from a healthy one.

## What Changes

- Remove `remotepairingd` from the hijack-detection process list, or replace
  the system-wide `pgrep <name>` existence check with a check for an actual
  established/listening connection tied to the specific sharing service.
- Every `ACCESS DENIED` hijack decision writes an audit-log entry recording
  which signal fired (process match / SSH env var / SSH ancestry) and the
  matched process name/PID, so a denial is diagnosable after the fact.
- Fix `handleStatusQuick` (and any other status path) to check
  `pingResp.Success` in addition to the transport-level error, so a
  hijack-denied ping is reported as denied/locked rather than "ACTIVE".
- **BREAKING**: machines with `remotepairingd` continuously running (a common
  baseline state, not an edge case) will see previously-blocked commands start
  succeeding once the detector no longer treats it as a hijack signal.

## Capabilities

### New Capabilities
- `session-hijack-detection`: daemon-side detection of remote/hijacked IPC
  sessions (process-based and SSH-ancestry-based signals), the resulting
  memory-wipe/deny behavior, and audit logging of the decision.

### Modified Capabilities
(none — no existing specs cover this behavior yet)

## Impact

- `internal/daemon/daemon_ipc.go` (`isHijacked`, `handleConnection`)
- `cmd/sec-agent/cmd_diagnostics.go` (`handleStatusQuick`)
- `cmd/sec-agent/main.go` (`queryDaemonRaw` callers that need `resp.Success`)
- `internal/audit` (new hijack-denial log entries)
- `docs/design_documentation.md`, `docs/user_guide.md`, `README.md` (hijack
  detection descriptions currently mismatch actual `remotepairingd` behavior)
- `cmd/sec-agent/cmd_security_audit_test.go` (add coverage for the process-list
  signal, currently only the SSH-ancestry path is tested)
