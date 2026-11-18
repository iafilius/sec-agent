## Purpose

Defines how the sec-agent daemon hands its in-memory state to a replacement process during `sec restart --hot-reload`, so that a reload either completes or fails with a clear error and never leaves the daemon unresponsive.

## ADDED Requirements

### Requirement: Hot-reload does not block daemon requests

While a hot-reload handoff is in progress, the daemon SHALL continue to answer IPC requests (including `status`) within a bounded time.

#### Scenario: Large state payload during reload
- **WHEN** a hot-reload is requested and the serialized state exceeds the OS pipe buffer size
- **THEN** the daemon completes or aborts the handoff without holding its state lock during the pipe write
- **AND** a concurrent `sec status` request receives a response

#### Scenario: Status while reload is running
- **WHEN** a hot-reload is in progress
- **THEN** a `sec status` request returns within the configured IPC timeout

### Requirement: Handoff has bounded time

The daemon SHALL apply a deadline to every write of the hot-reload handoff, and SHALL abort the reload and keep serving the current state when the deadline is exceeded.

#### Scenario: Replacement process does not read the payload
- **WHEN** the replacement process does not consume the handoff payload before the deadline
- **THEN** the daemon aborts the handoff, keeps running with its current state, and records a failure in the audit log

#### Scenario: Successful handoff
- **WHEN** the replacement process reads the full payload before the deadline
- **THEN** the daemon exits and the replacement process serves the same state

### Requirement: Client does not wait forever

The CLI SHALL apply a read deadline to daemon requests and SHALL report a timeout as an error.

#### Scenario: Daemon does not respond
- **WHEN** a CLI command sends a request and the daemon sends no response before the deadline
- **THEN** the CLI exits with a non-zero status and an error message that states the daemon did not respond

### Requirement: Accurate restart errors

`sec restart` SHALL report the actual failure reason. It SHALL NOT report "not currently running" for errors that are not caused by a missing daemon.

#### Scenario: Hot-reload fails for another reason
- **WHEN** a hot-reload fails for a reason other than the daemon not running
- **THEN** the error message contains the underlying failure reason
