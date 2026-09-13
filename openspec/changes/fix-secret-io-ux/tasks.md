## 1. Interactive `--stdin` prompt, masking, and timeout

- [x] 1.1 In `handleSet` (cmd/sec-agent/cmd_secrets.go), detect `term.IsTerminal(int(os.Stdin.Fd()))` for the `--stdin` path and print an instructional message (how to signal EOF, how to cancel) before reading, only on the interactive-TTY branch
- [x] 1.2 Mask interactive `--stdin` input by clearing only the terminal's `ECHO` flag via `golang.org/x/sys/unix` termios ioctls (`TIOCGETA`/`TIOCSETA`) around the existing `io.ReadAll(os.Stdin)` read, with the original termios state restored via `defer` (not `term.MakeRaw`, which also disables `ISIG` and would break Ctrl+C cancellation)
- [x] 1.3 Add a 120s timeout on the interactive-TTY read (goroutine + `select`/`time.After`), printing an informative error (explains the timeout, suggests retry or piping input) and exiting non-zero on expiry without storing a secret
- [x] 1.4 Verify piped/redirected `--stdin` (the non-TTY path) is unaffected: existing tests in `cmd_secrets_test.go` covering `--stdin` with piped input still pass unchanged
- [x] 1.5 Add a test simulating an interactive TTY (or a fake terminal fd) verifying the instructional message is printed before the blocking read
- [x] 1.6 Add a test verifying the interactive-TTY read times out and reports the informative error when no EOF arrives within the timeout window

## 2. Correct the `sec get` masking doc claim

- [x] 2.1 Replace the false "masked in non-interactive/redacted contexts" claim in `cmd/sec-agent/cmd_skills_init.go` with accurate guidance recommending `run`/env-injection as the default-safe consumption pattern, reserving `get` for deliberate human/`--raw` use
- [x] 2.2 Apply the same correction to `cmd/sec-agent/SKILL.md` and `docs/skills/sec-agent-integration/SKILL.md` (keep both copies identical, per existing convention)
- [x] 2.3 Verify no other doc (README.md, docs/user_guide.md, docs/design_documentation.md) repeats the false masking claim (grep for "masked in non-interactive" / "redacted contexts" and confirm no remaining false claims)

## 3. Verification

- [x] 3.1 Run the full test suite (`go test ./...`) and confirm all tests pass
- [x] 3.2 Manually verify: `sec set <path> --stdin` run interactively prints the instructional message and masks typed input; `echo val | sec set <path> --stdin` still works unchanged
