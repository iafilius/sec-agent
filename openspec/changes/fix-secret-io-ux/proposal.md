## Why

Two related secret-input/output UX findings surfaced in live testing on
v2.13.0. First, `sec set --stdin` blocks on `io.ReadAll(os.Stdin)` with zero
prompt or timeout, indistinguishable from a hang when a user types a value
directly rather than piping it in — reproduced live: typing into `--stdin`
interactively appeared to do nothing, while `echo "..." | sec set --stdin`
worked immediately, because only EOF (not Enter) unblocks the read and
nothing tells the user that. Second, the AI-agent-facing skill doc
(`cmd_skills_init.go`) claims `sec get` is "masked in non-interactive/redacted
contexts" — verified false: `handleGet` has no TTY detection anywhere and
always prints the real value. A mask-by-default fix for `get` was
considered and rejected for this change: it would break the tool's own
documented `export DB_PASS=$(sec get database/prod/password)` pattern, since
command substitution is indistinguishable from a non-interactive agent pipe
at the OS level. This change fixes what's cheaply and safely fixable now:
the `--stdin` hang and the false doc claim.

## What Changes

- `sec set --stdin` prints an instructional message before blocking on
  stdin (e.g. "Reading secret from stdin... press Ctrl+D when done, or
  Ctrl+C to cancel"), so the read-until-EOF behavior is no longer
  indistinguishable from a hang.
- `sec set --stdin` detects when its stdin fd is an interactive TTY (the
  same way the existing password-prompt fallback path already does via
  `term.IsTerminal`) and masks the input via `term.ReadPassword` in that
  case, instead of echoing a pasted/typed secret in plaintext to the
  screen and scrollback.
- `sec set --stdin` applies a timeout while waiting for input on an
  interactive TTY, and on expiry prints an informative error (what
  happened and how to retry/pipe instead) rather than continuing to block
  indefinitely.
- Corrects the false "masked in non-interactive/redacted contexts" claim
  for `sec get` in the embedded AI-agent skill doc
  (`cmd/sec-agent/SKILL.md` / `docs/skills/sec-agent-integration/SKILL.md`
  / `cmd_skills_init.go`), replacing it with accurate guidance steering
  agents/scripts toward `run`/env-injection for default-safe secret
  consumption, reserving `get` for deliberate human/`--raw` use. No `get`
  code behavior changes in this change.

## Capabilities

### New Capabilities
- `stdin-secret-input`: interactive-vs-piped behavior of `sec set --stdin`,
  covering the prompt, TTY masking, and timeout requirements.

### Modified Capabilities
(none — the `get` doc correction is a documentation fix with no spec-level
behavior change; `sec get`'s actual output behavior is unchanged)

## Impact

- `cmd/sec-agent/cmd_secrets.go` (`handleSet`)
- `cmd/sec-agent/cmd_skills_init.go` (embedded skill doc generation)
- `cmd/sec-agent/SKILL.md`, `docs/skills/sec-agent-integration/SKILL.md`
- `cmd/sec-agent/cmd_secrets_test.go` (new/extended `--stdin` tests)
