## 1. Fix hijack-detector false positive

- [x] 1.1 Remove `remotepairingd` from the `sharingServices` list in `isHijacked` (internal/daemon/daemon_ipc.go) and verify `pgrep remotepairingd` no longer influences the return value (unit test with a fake/stubbed process lookup, or a table-driven test isolating the list contents)
- [x] 1.2 Update `docs/design_documentation.md`, `docs/user_guide.md`, and `README.md` hijack-detection descriptions to drop the `remotepairingd`/"Xcode remote debugging" claim and match the corrected behavior
- [x] 1.3 Add a regression test asserting `remotepairingd` presence alone does not trigger `isHijacked` (extend or add alongside `cmd_security_audit_test.go`'s `TestDaemonSessionHijackingSSHCheck`)

## 2. Audit logging on hijack denial

- [x] 2.1 Add an `internal/audit` log entry written from `handleConnection` before `sendError` on a hijack denial, including the triggering signal type (process match / SSH env var / SSH ancestry) and matched process name/PID or variable name
- [x] 2.2 Verify via test that a simulated SSH-ancestry or process-match denial produces a corresponding `audit.log` entry with the expected fields

## 3. Fix status --quick false-healthy report

- [x] 3.1 Update `handleStatusQuick` (cmd/sec-agent/cmd_diagnostics.go) to check `pingResp.Success` in addition to `pingErr`, reporting `LOCKED`/denied status when the ping itself was denied
- [x] 3.2 Add/extend a test alongside `TestHandleStatusQuick_OrphanedSocketDetection` covering a hijack-denied ping and verifying `status --quick` reports locked/denied, not active

## 4. Verification

- [x] 4.1 Run the full test suite (`go test ./...`) and confirm all tests pass
- [x] 4.2 Manually verify on a machine with `remotepairingd` running that `sec status`, `sec get`, `sec run`, and `sec audit` no longer report `ACCESS DENIED: Remote session hijacking or screen sharing detected`
