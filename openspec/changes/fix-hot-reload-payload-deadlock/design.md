# Design

## Context

`IPCActionReexec` in `internal/daemon/daemon.go` (~466–548) takes `d.mu`, JSON-encodes the full state into an `os.Pipe`, and only then starts the replacement process (`cmd.Start()`, ~536) that reads the pipe. Payloads above the 64 KB pipe buffer block the write forever while the lock is held. The expiry ticker (`daemon_lock.go:65`) and `processRequest` (`daemon.go:399`) then wait on the same mutex. See proposal.md for motivation.

## Goals / Non-Goals

**Goals:**
- No pipe write happens while `d.mu` is held.
- The replacement process is started and reading before the payload is written, or the payload does not depend on pipe capacity.
- A stuck handoff times out, keeps the current daemon serving, and writes an audit entry.
- The CLI never waits forever on a daemon response.

**Non-Goals:**
- No change to vault file format, key derivation, or the audit log format.
- No change to the non-hot-reload restart path.

## Decisions

- **Snapshot under lock, write outside lock.** Serialize the payload to a `[]byte` while holding `d.mu`, release it, then do all pipe I/O. Alternative: keep the lock and use a larger pipe; rejected because pipe capacity is OS-dependent and the bug scales with profile size.
- **Start the child before writing.** Keeps the reader alive so the pipe drains. Alternative: pass the payload via a temp file with `0600` permissions; rejected because it leaves key material on disk.
- **Write deadline on the handoff pipe.** Use `SetWriteDeadline` on the pipe end (or a goroutine plus timer). On expiry, kill the child, keep serving, and log to audit.
- **Read deadline in `queryDaemon`** (`cmd/sec-agent/main.go`, ~799). Choose a deadline larger than normal latency and surface it as "daemon did not respond".
- **Fix `handleRestart` error reporting** (`cmd/sec-agent/main.go`, ~1430–1448) so it returns the real error.

## Risks / Trade-offs

- [Child exits before reading all bytes] → Detect via write error or deadline, abort without `os.Exit`, and keep state.
- [Snapshot copy doubles memory briefly] → Acceptable for payloads of this size.
- [Hot-reload retains secrets in a buffer] → Zero the buffer after the handoff, as the current code path already holds the same material.

## Migration Plan

Ship as a normal release. Rollback is reverting the commit; no state migration is needed. Verify with a profile large enough to exceed 64 KB: `sec restart --hot-reload` completes and `sec status` responds during and after the reload.

## Open Questions

- Exact deadline values (suggested: 5 s for the handoff write, 10 s for the CLI read). The developer can tune these during implementation.
