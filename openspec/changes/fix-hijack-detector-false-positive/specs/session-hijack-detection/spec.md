## Purpose

Defines how sec-agent's daemon distinguishes an actively hijacked/remote IPC
session from normal local usage, and how it reports and records that decision
so denials are trustworthy and diagnosable.

## ADDED Requirements

### Requirement: Hijack detection reflects active remote sessions, not background service presence
The system SHALL determine that an IPC session is hijacked only when there is
evidence of an active remote-control, screen-sharing, or remote-shell
connection to the caller. The system SHALL NOT treat the mere presence of an
unrelated, dormant background service as evidence of an active remote
session.

#### Scenario: Continuity background service present, no active remote session
- **WHEN** a client issues a request while Apple's Continuity/RemotePairing
  background service is running on the host but no screen-sharing, VNC, or
  remote-control connection to this session is active
- **THEN** the system SHALL NOT deny the request as hijacked and SHALL NOT
  wipe the in-memory vault cache on account of that service's presence

#### Scenario: Active screen-sharing or remote-shell session detected
- **WHEN** a client issues a request while an active screen-sharing, VNC, or
  SSH-ancestry remote-shell session is detected for that connection
- **THEN** the system SHALL deny the request, wipe the in-memory vault cache,
  and report an access-denied error

### Requirement: Every hijack-detection denial is recorded with its trigger reason
The system SHALL write an audit-log entry for every request denied due to
hijack detection, recording which signal triggered the denial (e.g. process
match, SSH environment variable, SSH process ancestry) and the identifying
detail of the match (matched process name and PID, or matched environment
variable name).

#### Scenario: Denial produces a diagnosable audit record
- **WHEN** the system denies a request due to hijack detection
- **THEN** an audit-log entry is written for that denial, including the
  triggering signal type and the matched process/PID or variable, before the
  denial response is returned to the caller

### Requirement: Quick status reporting reflects an active hijack denial
The system's fast-path status check SHALL report the session as locked or
denied when the daemon's underlying connectivity check itself was denied due
to hijack detection, rather than reporting the session as active.

#### Scenario: Quick status check during a hijack-denied connection
- **WHEN** a user runs the fast-path status check while the daemon would deny
  IPC requests to this session due to hijack detection
- **THEN** the fast-path status check SHALL report the session as
  locked/denied, and SHALL NOT report the socket or session as active
