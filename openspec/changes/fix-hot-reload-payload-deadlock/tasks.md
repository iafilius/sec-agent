# Tasks

## 1. Daemon handoff

- [ ] 1.1 Serialize the hot-reload payload under `d.mu`, then release the lock before any pipe I/O in `IPCActionReexec` (`internal/daemon/daemon.go`)
- [ ] 1.2 Start the replacement process before writing the payload, and keep the write outside the lock
- [ ] 1.3 Add a write deadline to the handoff; on timeout, kill the child, keep serving, and write an audit entry
- [ ] 1.4 Zero the payload buffer after the handoff completes or aborts

## 2. CLI

- [ ] 2.1 Add a read deadline to `queryDaemon` (`cmd/sec-agent/main.go`) and report "daemon did not respond" on timeout
- [ ] 2.2 Fix `handleRestart` so it returns the real error instead of always printing "not currently running"

## 3. Tests

- [ ] 3.1 Add a test where the payload exceeds 64 KB and a concurrent status request still returns
- [ ] 3.2 Add a test where the replacement does not read the payload, and assert the daemon keeps serving and the audit entry is written
- [ ] 3.3 Add a test for the `queryDaemon` timeout error

## 4. Verification

- [ ] 4.1 Run `go test ./internal/daemon/ ./cmd/sec-agent/`
- [ ] 4.2 Manually run `sec restart --hot-reload` on a profile larger than 64 KB and confirm `sec status` responds before and after
