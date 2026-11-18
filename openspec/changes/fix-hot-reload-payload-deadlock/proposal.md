## Why

`sec restart --hot-reload` can deadlock the daemon. The reexec handler in `internal/daemon/daemon.go` holds `d.mu` while it JSON-encodes the full state payload (master key, profile, secrets) into an `os.Pipe`. The child process that reads the pipe is only started after that write. Once the payload exceeds the 64 KB pipe buffer, the write blocks forever, every other request and the expiry ticker wait on `d.mu`, and `sec status` hangs as well. Observed on v2.19.3 with a ~94 KB profile store; the goroutine dump shows `Encoder.Encode` in `IO wait` while two goroutines wait on the mutex.

## What Changes

- Build the hot-reload payload while holding `d.mu`, then release the lock before any pipe I/O.
- Start the child process before the state handoff, or hand the payload over through a buffer that does not depend on pipe capacity.
- Add write deadlines to the handoff so a stuck child cannot block the daemon indefinitely.
- Add a read deadline in the client `queryDaemon` (`cmd/sec-agent/main.go`) so a stuck daemon cannot block the CLI.
- `handleRestart` in `cmd/sec-agent/main.go` must report the real error instead of always printing "not currently running".

No user-visible command or flag changes.

## Capabilities

### New Capabilities

- `daemon-hot-reload`: how the daemon hands its in-memory state to a replacement process on `sec restart --hot-reload`, including lock ordering, timeouts, and error reporting.

### Modified Capabilities

None.

## Impact

- `internal/daemon/daemon.go` (IPC reexec action, mutex scope, child start order)
- `internal/daemon/daemon_ipc.go` (connection deadlines, if applicable)
- `cmd/sec-agent/main.go` (`queryDaemon` read deadline, `handleRestart` error reporting)
- No changes to the vault file format, the audit log format, or the CLI interface.
