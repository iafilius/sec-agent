## Context

`handleSet` in [cmd_secrets.go#L280-L286](../../../cmd/sec-agent/cmd_secrets.go)
calls `io.ReadAll(os.Stdin)` unconditionally when `--stdin` is passed, with no
prior output and no distinction between an interactive terminal and a pipe.
The existing interactive password-prompt fallback path (used when no value
and no `--stdin` are given) already does the right thing for a single-line
secret: `term.IsTerminal(int(os.Stdin.Fd()))`, a prompt, and masked entry via
`term.ReadPassword`. `--stdin` supports multi-line/EOF-terminated values
(e.g. pasting a multi-line PEM certificate), which `term.ReadPassword` does
not support (it reads one line, Enter-terminated) — so the fix for `--stdin`
needs its own masking approach, not a reuse of `ReadPassword`. See
proposal.md - Why for the live-reproduced symptom this addresses.

## Goals / Non-Goals

**Goals:**
- Make the interactive-TTY `--stdin` path announce itself, mask input, and
  bound its wait with a timeout + informative error.
- Leave piped/redirected `--stdin` behavior (the documented, working path)
  completely unchanged.

**Non-Goals:**
- Not changing `--stdin`'s value semantics (EOF-terminated, optional
  `--no-trim`) — only the interactive-TTY presentation around it.
- Not adding a `--timeout` flag or other new configurability; a fixed
  default is sufficient for this fix and avoids unnecessary surface area.
- Not touching `sec get` behavior — the `get`-masking doc claim is corrected
  as a documentation-only task in this same change (see tasks.md), with no
  code change to `handleGet`.

## Decisions

**Detect interactive stdin the same way the existing fallback path does:**
`term.IsTerminal(int(os.Stdin.Fd()))`. This is already proven correct in
this codebase (used by the no-value interactive fallback), so reusing it
keeps the two code paths consistent instead of introducing a second
detection mechanism.

**Mask interactive `--stdin` input by clearing only the terminal's `ECHO`
flag via `golang.org/x/sys/unix` termios ioctls (`TIOCGETA`/`TIOCSETA`),
restoring the original state via `defer`, rather than `term.MakeRaw`.**
`term.MakeRaw` also clears `ISIG`, which stops Ctrl+C from generating
`SIGINT` at all (it becomes a literal byte in the input stream instead) —
that would silently break the "or Ctrl+C to cancel" behavior the
instructional message promises. Clearing only `ECHO` keeps canonical mode
and signal generation intact: Ctrl+D still ends input the same way it does
today, Ctrl+C still cancels the process, and only the terminal echo of
typed characters is suppressed. `golang.org/x/sys/unix` is already a
project dependency (used in `internal/daemon/daemon_ipc.go`), so this adds
no new dependency. `term.ReadPassword`'s existing masking (used by the
no-value interactive fallback) takes the same narrowly-scoped approach,
just for canonical single-line reads rather than our EOF-terminated read.

**Implement the timeout by running the blocking read in a goroutine and
racing it against `time.After` with `select`, since Go cannot cancel a
blocked `os.Stdin.Read` directly.** On timeout, print the informative error
and exit; the reader goroutine is abandoned and cleaned up by process exit,
which is acceptable for a CLI command. Default timeout: 120 seconds — long
enough to paste a multi-line secret by hand, short enough to fail fast when
a user is genuinely stuck wondering if the command hung.

**Fix the `get`-masking doc claim as a plain text correction, no code
change.** Per the confirmed decision in exploration: option A (docs-only)
was chosen over mask-by-default because the latter would break the tool's
own documented `export DB_PASS=$(sec get ...)` pattern. This task only
touches `cmd_skills_init.go` and the two `SKILL.md` copies.

## Risks / Trade-offs

[Echo-only termios manipulation could leave the terminal in a bad state if
the process is killed uncleanly (e.g. `kill -9`) before the original state
is restored] → Accept: this is an inherent limitation of any termios-based
masking (the existing `term.ReadPassword` path shares it too); document
that `reset` or opening a new terminal recovers from it, same as today.

[A 120s timeout could interrupt a legitimately slow human (e.g. copying a
secret from a password manager with friction)] → The informative timeout
error explicitly suggests retrying or piping input instead, so the user has
an immediate, documented recovery path rather than a dead end.

[Goroutine leaked on timeout keeps the abandoned read blocked until process
exit] → Acceptable for a short-lived CLI invocation; the process exits
immediately after reporting the timeout, so the goroutine's lifetime is
bounded to that exit.

## Migration Plan

- Ship as a normal point release; no data or vault format changes.
- No user action required — existing piped `--stdin` usage and scripts are
  unaffected; only the interactive-TTY path changes, and only additively
  (a prompt, masking, and a timeout that did not exist before).
